package org.tidecloak.iga.services;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.storage.UserStorageUtil;

/**
 * Shared per-realm cache-eviction helpers used by the IGA toggle endpoint
 * ({@code TideAdminCompatResource}) AND the {@code DISABLE_IGA} commit-replay
 * teardown ({@code IgaReplayDispatcher.replayDisableIga}).
 *
 * <p>These were originally {@code private static} on
 * {@code TideAdminCompatResource}. They were extracted here verbatim so the
 * replay path (a different package) can call the IDENTICAL eviction the toggle
 * used to do inline, now that the ON&rarr;OFF teardown runs on
 * {@code DISABLE_IGA} commit rather than at toggle time.</p>
 *
 * <p>Both methods are best-effort: a cache-provider absence or an individual
 * eviction failure is logged and swallowed — a cache-eviction failure must
 * never abort the toggle / commit (the realm-attribute flip is already
 * committed and the response is about to be sent).</p>
 */
public final class IgaRealmCacheEviction {

    private static final Logger logger = Logger.getLogger(IgaRealmCacheEviction.class);

    private IgaRealmCacheEviction() {
    }

    /**
     * Evict every cached user entry for the realm so subsequent
     * {@code session.users().getUserBy*} lookups re-load through
     * {@code IgaUserProvider} and the {@code IgaUserAdapter#isEnabled}
     * quarantine override fires (OFF&rarr;ON) / reflects the IGA-off state
     * (ON&rarr;OFF). Best-effort.
     */
    public static void evictRealmUserCache(KeycloakSession session, RealmModel realm) {
        try {
            UserCache cache = UserStorageUtil.userCache(session);
            if (cache == null) {
                logger.debugf("IGA realm user-cache eviction: realm=%s — UserCache provider not installed (skipped)",
                        realm.getName());
                return;
            }
            cache.evict(realm);
            logger.infof("IGA realm user-cache eviction: realm=%s — evicted (next user lookup will re-load through IgaUserProvider so the quarantine override fires)",
                    realm.getName());
        } catch (RuntimeException ex) {
            logger.errorf(ex,
                    "IGA realm user-cache eviction FAILED for realm %s — quarantine reads may be stale until cache entries expire.",
                    realm.getName());
        }
    }

    /**
     * Evict every cached client / role / group / client-scope / org / idp entry
     * for the realm so subsequent reads re-load through the IGA wrappers and the
     * quarantine overrides fire (or, on ON&rarr;OFF, reflect the IGA-off state).
     * Best-effort, per-entity tolerant. Extracted verbatim from
     * {@code TideAdminCompatResource.evictRealmCache}.
     */
    public static void evictRealmCache(KeycloakSession session, RealmModel realm) {
        CacheRealmProvider cache;
        try {
            cache = session.getProvider(CacheRealmProvider.class);
        } catch (RuntimeException lookupEx) {
            logger.warnf(lookupEx,
                    "IGA realm-cache eviction: realm=%s — CacheRealmProvider lookup failed (skipped); quarantine reads on cached clients/roles/groups/scopes may be stale until entries expire.",
                    realm.getName());
            return;
        }
        if (cache == null) {
            logger.debugf("IGA realm-cache eviction: realm=%s — CacheRealmProvider not installed (skipped)",
                    realm.getName());
            return;
        }

        String realmId = realm.getId();
        int clients = 0, roles = 0, groups = 0, scopes = 0, orgs = 0, idps = 0;

        // Realm singleton (its by-id + by-name cache keys). REQUIRED so a realm
        // ATTRIBUTE write (e.g. the toggle's iga.attestor=tide / isIGAEnabled=true)
        // committed in a separate transaction is visible to a freshly-opened
        // runJobInTransaction session: RealmCacheSession.getRealm returns a
        // CachedRealm snapshot whose getAttribute() reads the values captured at
        // cache-load time and does NOT delegate per-call. Without this the
        // toggle-on sweep/converge job session reads a STALE iga.attestor (null →
        // "simple") and signs via SimpleNameAttestor instead of TideAttestor, and
        // resolveMode reports the realm as non-tide so the firstAdmin backfill is
        // skipped. Best-effort, same contract as the per-entity evictions below.
        try {
            cache.registerRealmInvalidation(realmId, realm.getName());
        } catch (RuntimeException ex) {
            logger.debugf(ex,
                    "IGA realm-cache eviction: realm=%s — registerRealmInvalidation failed (continuing); a separately-committed realm-attribute write may be stale in a fresh job session until the entry expires.",
                    realm.getName());
        }

        // Clients.
        try {
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    cache.registerClientInvalidation(client.getId(), client.getClientId(), realmId);
                    clients++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: client=%s (uuid=%s) realm=%s — registerClientInvalidation failed (continuing).",
                            client.getClientId(), client.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — client iteration failed after evicting %d (continuing with roles/groups/scopes).",
                    realm.getName(), clients);
        }

        // Realm-level roles + per-client roles.
        try {
            for (RoleModel role : session.roles().getRealmRolesStream(realm).toList()) {
                try {
                    cache.registerRoleInvalidation(role.getId(), role.getName(), realmId);
                    roles++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: realm-role=%s (id=%s) realm=%s — registerRoleInvalidation failed (continuing).",
                            role.getName(), role.getId(), realm.getName());
                }
            }
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    for (RoleModel role : session.roles().getClientRolesStream(client).toList()) {
                        try {
                            cache.registerRoleInvalidation(role.getId(), role.getName(), client.getId());
                            roles++;
                        } catch (RuntimeException ex) {
                            logger.debugf(ex,
                                    "IGA realm-cache eviction: client-role=%s (id=%s) container=%s realm=%s — registerRoleInvalidation failed (continuing).",
                                    role.getName(), role.getId(), client.getId(), realm.getName());
                        }
                    }
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: realm=%s client=%s — client-roles iteration failed (continuing).",
                            realm.getName(), client.getClientId());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — role iteration failed after evicting %d (continuing with groups/scopes).",
                    realm.getName(), roles);
        }

        // Groups.
        try {
            for (GroupModel group : realm.getGroupsStream().toList()) {
                try {
                    cache.registerGroupInvalidation(group.getId());
                    groups++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: group=%s (id=%s) realm=%s — registerGroupInvalidation failed (continuing).",
                            group.getName(), group.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — group iteration failed after evicting %d (continuing with scopes).",
                    realm.getName(), groups);
        }

        // Client scopes.
        try {
            for (ClientScopeModel scope : realm.getClientScopesStream().toList()) {
                try {
                    cache.registerClientScopeInvalidation(scope.getId(), realmId);
                    scopes++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: scope=%s (id=%s) realm=%s — registerClientScopeInvalidation failed (continuing).",
                            scope.getName(), scope.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — client-scope iteration failed after evicting %d.",
                    realm.getName(), scopes);
        }

        // Organizations (keyed on org id alone via the public registerInvalidation).
        try {
            OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
            if (orgProvider != null) {
                for (OrganizationModel org : orgProvider.getAllStream().toList()) {
                    try {
                        cache.registerInvalidation(org.getId());
                        orgs++;
                    } catch (RuntimeException ex) {
                        logger.debugf(ex,
                                "IGA realm-cache eviction: org=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                                org.getName(), org.getId(), realm.getName());
                    }
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — organization iteration failed after evicting %d.",
                    realm.getName(), orgs);
        }

        // Identity providers (internalId + alias key).
        try {
            for (IdentityProviderModel idp : realm.getIdentityProvidersStream().toList()) {
                try {
                    if (idp.getInternalId() != null) {
                        cache.registerInvalidation(idp.getInternalId());
                    }
                    if (idp.getAlias() != null) {
                        cache.registerInvalidation(realmId + "." + idp.getAlias() + ".idp.alias");
                    }
                    idps++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA realm-cache eviction: idp=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                            idp.getAlias(), idp.getInternalId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA realm-cache eviction: realm=%s — idp iteration failed after evicting %d.",
                    realm.getName(), idps);
        }

        logger.infof("IGA realm-cache eviction: realm=%s — evicted clients=%d roles=%d groups=%d scopes=%d orgs=%d idps=%d",
                realm.getName(), clients, roles, groups, scopes, orgs, idps);
    }
}
