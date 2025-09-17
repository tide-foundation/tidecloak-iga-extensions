package org.tidecloak.preview.service;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.InternalServerErrorException;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.DefaultClientSessionContext;

import org.tidecloak.jpa.entities.preview.TokenPreviewEntity;
import org.tidecloak.preview.dto.TokenPreviewSpec;
import org.tidecloak.preview.util.TokenDiffUtil;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Recomputes & persists token previews based on stored TokenPreviewSpec JSON.
 * No dependency on TokenPreviewBuilder or ReplayClientSessionContext.
 */
public class PreviewRegenService {

    private final KeycloakSession session;

    public PreviewRegenService(KeycloakSession session) {
        this.session = session;
    }

    /** Recompute all previews in the current realm. Returns count updated. */
    public int regenerateAllForRealm(RealmModel realm) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        @SuppressWarnings("unchecked")
        List<TokenPreviewEntity> items = em.createQuery("SELECT e FROM TokenPreviewEntity e WHERE e.realmId = :rid")
                .setParameter("rid", realm.getId())
                .getResultList();

        int updated = 0;
        for (TokenPreviewEntity e : items) {
            if (regenerateOne(realm, e)) {
                updated++;
            }
        }
        return updated;
    }

    /** Recompute one preview entity in-place using its stored specJson. */
    public boolean regenerateOne(RealmModel realm, TokenPreviewEntity entity) {
        try {
            if (entity == null) return false;

            TokenPreviewSpec spec = org.keycloak.util.JsonSerialization.readValue(entity.specJson, TokenPreviewSpec.class);
            if (spec == null) throw new BadRequestException("Invalid spec JSON for preview id " + entity.id);

            // userless default context? just restamp timestamp; (can rebuild similarly if needed)
            if (spec.userId == null) {
                entity.createdAt = OffsetDateTime.now();
                EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
                em.merge(entity);
                return true;
            }

            ClientModel client = session.clients().getClientByClientId(realm, spec.clientId);
            if (client == null) throw new BadRequestException("Client not found: " + spec.clientId);
            UserModel user = session.users().getUserById(realm, spec.userId);
            if (user == null) throw new BadRequestException("User not found: " + spec.userId);

            // Build skeleton sessions for computation
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm, user, user.getUsername(), "127.0.0.1", "preview-regen", false, null, null);
            AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);

            // notes (optional in regen)
            if (spec.userSessionNotes != null) spec.userSessionNotes.forEach(userSession::setNote);
            if (spec.clientSessionNotes != null) spec.clientSessionNotes.forEach(clientSession::setNote);
            if (spec.authTimeEpoch != null) userSession.setNote("auth_time_override", String.valueOf(spec.authTimeEpoch));
            if (spec.acr != null) clientSession.setNote("acr", spec.acr);
            if (spec.amr != null && !spec.amr.isEmpty()) clientSession.setNote("amr", String.join(" ", spec.amr));

            // requested scopes
            Set<ClientScopeModel> requestedScopes = new LinkedHashSet<>();
            if (Boolean.TRUE.equals(spec.includeDefaultScopes)) client.getClientScopes(true).values().forEach(requestedScopes::add);
            if (Boolean.TRUE.equals(spec.includeOptionalScopes)) client.getClientScopes(false).values().forEach(requestedScopes::add);
            if (spec.addOptionalClientScopes != null) {
                for (String s : spec.addOptionalClientScopes) {
                    realm.getClientScopesStream().filter(cs -> Objects.equals(cs.getName(), s)).findFirst().ifPresent(requestedScopes::add);
                }
            }
            if (spec.removeOptionalClientScopes != null) requestedScopes.removeIf(cs -> spec.removeOptionalClientScopes.contains(cs.getName()));
            if (spec.extraClientScopes != null) {
                for (String s : spec.extraClientScopes) {
                    realm.getClientScopesStream().filter(cs -> Objects.equals(cs.getName(), s)).findFirst().ifPresent(requestedScopes::add);
                }
            }

            // scope string (for APIs that accept "scope" param instead of Set<ClientScopeModel>)
            String scopeString = requestedScopes.stream()
                    .filter(cs -> !(cs instanceof ClientModel))
                    .filter(ClientScopeModel::isIncludeInTokenScope)
                    .map(ClientScopeModel::getName)
                    .collect(Collectors.joining(" "));

            // temp overlay of attributes
            Map<String, String> origRealmAttrs = new HashMap<>(realm.getAttributes() == null ? Map.of() : realm.getAttributes());
            Map<String, String> origClientAttrs = new HashMap<>(client.getAttributes() == null ? Map.of() : client.getAttributes());
            try {
                if (spec.realmAttributes != null) spec.realmAttributes.forEach((k,v) -> realm.setAttribute(k, String.valueOf(v)));
                if (spec.clientAttributes != null) spec.clientAttributes.forEach((k,v) -> client.setAttribute(k, String.valueOf(v)));

                // BASELINE
                ClientSessionContext baselineCtx =
                        DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, scopeString, session);

                AccessToken baselineToken = new TokenManager()
                        .createClientAccessToken(session, realm, client, user, userSession, baselineCtx);

                String baselineJson = org.keycloak.util.JsonSerialization.writeValueAsString(baselineToken);

                // PREVIEW = baseline mutated
                AccessToken previewToken = org.keycloak.util.JsonSerialization.readValue(baselineJson, AccessToken.class);

                // compute role deltas from spec
                Set<RoleModel> addRoles = new HashSet<>();
                if (spec.addUserRoles != null) {
                    for (Object rr : spec.addUserRoles) {
                        RoleModel r = resolveRoleGeneric(realm, rr);
                        if (r != null) addRoles.add(r);
                    }
                }

                Set<RoleModel> removeRoles = new HashSet<>();
                if (spec.removeUserRoles != null) {
                    for (Object rr : spec.removeUserRoles) {
                        RoleModel r = resolveRoleGeneric(realm, rr);
                        if (r != null) removeRoles.add(r);
                    }
                }

                Set<RoleModel> addGroupRoles = new HashSet<>();
                if (spec.addGroups != null) {
                    for (String gref : spec.addGroups) {
                        GroupModel g = resolveGroupByPathOrName(realm, gref);
                        if (g != null) addGroupRoles.addAll(expandCompositeRoles(g.getRoleMappingsStream()));
                    }
                }

                Set<RoleModel> removeGroupRoles = new HashSet<>();
                if (spec.removeGroups != null) {
                    for (String gref : spec.removeGroups) {
                        GroupModel g = resolveGroupByPathOrName(realm, gref);
                        if (g != null) removeGroupRoles.addAll(expandCompositeRoles(g.getRoleMappingsStream()));
                    }
                }

                RoleBuckets addB = bucketizeRoles(realm, addRoles);
                RoleBuckets delB = bucketizeRoles(realm, removeRoles);
                RoleBuckets addGB = bucketizeRoles(realm, addGroupRoles);
                RoleBuckets delGB = bucketizeRoles(realm, removeGroupRoles);

                Set<String> addRealm = new HashSet<>();
                addRealm.addAll(addB.realmRoleNames);
                addRealm.addAll(addGB.realmRoleNames);

                Set<String> delRealm = new HashSet<>();
                delRealm.addAll(delB.realmRoleNames);
                delRealm.addAll(delGB.realmRoleNames);

                Map<String, Set<String>> addClientRoles = new HashMap<>();
                addB.clientRoleNames.forEach((k,v) -> addClientRoles.computeIfAbsent(k, __ -> new HashSet<>()).addAll(v));
                addGB.clientRoleNames.forEach((k,v) -> addClientRoles.computeIfAbsent(k, __ -> new HashSet<>()).addAll(v));

                Map<String, Set<String>> delClientRoles = new HashMap<>();
                delB.clientRoleNames.forEach((k,v) -> delClientRoles.computeIfAbsent(k, __ -> new HashSet<>()).addAll(v));
                delGB.clientRoleNames.forEach((k,v) -> delClientRoles.computeIfAbsent(k, __ -> new HashSet<>()).addAll(v));

                mutateTokenRoles(previewToken, addRealm, delRealm, addClientRoles, delClientRoles);

                String previewJson = org.keycloak.util.JsonSerialization.writeValueAsString(previewToken);

                @SuppressWarnings("unchecked")
                Map<String,Object> baselineMap = org.keycloak.util.JsonSerialization.readValue(baselineJson, Map.class);
                @SuppressWarnings("unchecked")
                Map<String,Object> previewMap  = org.keycloak.util.JsonSerialization.readValue(previewJson, Map.class);

                // diffTokens returns a LIST; keep type aligned
                List<Map<String,Object>> diff = TokenDiffUtil.diffTokens(baselineMap, previewMap);

                // persist in-place
                EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
                entity.createdAt = OffsetDateTime.now();
                entity.baselineJson = baselineJson;
                entity.previewJson  = previewJson;
                entity.diffJson     = org.keycloak.util.JsonSerialization.writeValueAsString(diff);
                em.merge(entity);

                return true;
            } finally {
                // restore string attributes
                try {
                    // wipe anything we overrode
                    if (spec.realmAttributes != null) {
                        for (String k : spec.realmAttributes.keySet()) realm.setAttribute(k, (String) null);
                    }
                    if (spec.clientAttributes != null) {
                        for (String k : spec.clientAttributes.keySet()) client.setAttribute(k, (String) null);
                    }
                    // restore originals
                    origRealmAttrs.forEach(realm::setAttribute);
                    origClientAttrs.forEach(client::setAttribute);
                } catch (Throwable ignored) {}
            }

        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new InternalServerErrorException(e);
        }
    }
    /**
     * Recompute all previews for a specific user in the given realm.
     * Returns the number of updated preview rows.
     *
     * This is the method LinkTideAccount calls via reflection after a Tide link completes.
     */
    public int regenerateForUser(RealmModel realm, UserModel user) {
        if (realm == null || user == null) return 0;
        return regenerateForUser(realm, user.getId());
    }

    /**
     * Recompute all previews for a specific userId in the given realm.
     * Returns the number of updated preview rows.
     */
    public int regenerateForUser(RealmModel realm, String userId) {
        if (realm == null || userId == null) return 0;

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<TokenPreviewEntity> items = em.createQuery(
                        "SELECT e FROM TokenPreviewEntity e WHERE e.realmId = :rid AND e.userId = :uid",
                        TokenPreviewEntity.class)
                .setParameter("rid", realm.getId())
                .setParameter("uid", userId)
                .getResultList();

        int updated = 0;
        for (TokenPreviewEntity e : items) {
            if (regenerateOne(realm, e)) {
                updated++;
            }
        }
        return updated;
    }

    // -------- helpers ----------

    private static Set<RoleModel> expandCompositeRoles(Stream<RoleModel> direct) {
        Set<RoleModel> out = new HashSet<>();
        RoleUtils.expandCompositeRolesStream(direct).forEach(out::add);
        return out;
    }

    private static class RoleBuckets {
        final Set<String> realmRoleNames = new HashSet<>();
        final Map<String, Set<String>> clientRoleNames = new HashMap<>();
    }

    private RoleBuckets bucketizeRoles(RealmModel realm, Collection<RoleModel> roles) {
        RoleBuckets b = new RoleBuckets();
        for (RoleModel r : roles) {
            if (r.isClientRole()) {
                ClientModel c = realm.getClientById(r.getContainerId());
                if (c != null) {
                    b.clientRoleNames.computeIfAbsent(c.getClientId(), __ -> new HashSet<>()).add(r.getName());
                }
            } else {
                b.realmRoleNames.add(r.getName());
            }
        }
        return b;
    }

    private void mutateTokenRoles(AccessToken token,
                                  Set<String> addRealm, Set<String> removeRealm,
                                  Map<String, Set<String>> addClient, Map<String, Set<String>> removeClient) {

        AccessToken.Access ra = token.getRealmAccess();
        if (ra == null) { ra = new AccessToken.Access(); token.setRealmAccess(ra); }
        if (addRealm != null) ra.getRoles().addAll(addRealm);
        if (removeRealm != null) ra.getRoles().removeAll(removeRealm);

        Map<String, AccessToken.Access> res = token.getResourceAccess();
        if (res == null) { res = new LinkedHashMap<>(); token.setResourceAccess(res); }

        if (addClient != null) {
            for (Map.Entry<String, Set<String>> e : addClient.entrySet()) {
                AccessToken.Access a = res.computeIfAbsent(e.getKey(), __ -> new AccessToken.Access());
                a.getRoles().addAll(e.getValue());
            }
        }
        if (removeClient != null) {
            for (Map.Entry<String, Set<String>> e : removeClient.entrySet()) {
                AccessToken.Access a = res.get(e.getKey());
                if (a != null) a.getRoles().removeAll(e.getValue());
            }
        }
    }

    private GroupModel resolveGroupByPathOrName(RealmModel realm, String ref) {
        if (ref == null) return null;
        GroupModel g = KeycloakModelUtils.findGroupByPath(session, realm, ref);
        if (g != null) return g;
        for (GroupModel gm : realm.getGroupsStream().toList()) {
            if (ref.equals(gm.getName())) return gm;
        }
        return null;
    }

    /** Resolve a role from RoleRef/Map/String without coupling to DTO class. */
    private RoleModel resolveRoleGeneric(RealmModel realm, Object ref) {
        if (ref == null) return null;

        String name = null, clientId = null, kind = null;

        try {
            if (ref instanceof String s) {
                name = s;
            } else if (ref instanceof Map<?,?> m) {
                Object n = m.get("name"); if (n instanceof String) name = (String) n;
                Object c = m.get("clientId"); if (c instanceof String) clientId = (String) c;
                Object k = m.get("kind"); if (k instanceof String) kind = (String) k;
            } else {
                try { name = (String) ref.getClass().getMethod("getName").invoke(ref); } catch (Exception ignored) {}
                try { clientId = (String) ref.getClass().getMethod("getClientId").invoke(ref); } catch (Exception ignored) {}
                try { kind = (String) ref.getClass().getMethod("getKind").invoke(ref); } catch (Exception ignored) {}
                if (name == null) { try { name = (String) ref.getClass().getField("name").get(ref); } catch (Exception ignored) {} }
                if (clientId == null) { try { clientId = (String) ref.getClass().getField("clientId").get(ref); } catch (Exception ignored) {} }
                if (kind == null) { try { kind = (String) ref.getClass().getField("kind").get(ref); } catch (Exception ignored) {} }
            }
        } catch (Throwable ignored) {}

        RoleModel r;
        if ("realm".equalsIgnoreCase(kind) && name != null) {
            r = realm.getRole(name);
            if (r != null) return r;
        }
        if (clientId != null && name != null) {
            ClientModel c = session.clients().getClientByClientId(realm, clientId);
            if (c != null) {
                r = c.getRole(name);
                if (r != null) return r;
            }
        }
        if (name != null) {
            r = realm.getRole(name);
            if (r != null) return r;
            for (ClientModel c : realm.getClientsStream().toList()) {
                r = c.getRole(name);
                if (r != null) return r;
            }
        }
        return null;
    }
}
