package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.tidecloak.base.iga.UserContextBuilder;
import org.tidecloak.base.iga.UserContextDeltaUtils;
import org.tidecloak.base.iga.UserContextDraftService;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.utils.UserContextUtilBase;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Minimal utilities kept after ChangeSetProcessors deprecation.
 * - Restaging drafts uses UserContextDraftService.stage(...)
 * - Role expansion uses plain Keycloak RoleUtils
 * - Token mutation helpers removed (UserContextBuilder shapes payload now)
 * - No Tide wrappers / adapters
 */
public class UserContextUtils extends UserContextUtilBase {

    private static final ObjectMapper M = new ObjectMapper();

    /**
     * Recreate drafts for the given user using the new engine:
     *  - Deletes the old ChangesetRequest + AccessProofDetailEntity rows for each changeSet group
     *  - Restages drafts via UserContextDraftService.stage(...) using the original per-(user,client) deltas
     *  - Signing/commit is handled by normal approval flow
     */
    public void recreateUserContext(KeycloakSession session, UserModel userModel) {
        final RealmModel realm = session.getContext().getRealm();
        final EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // fetch all drafts for this user (use UserEntity for the named query)
        UserEntity uEnt = em.getReference(UserEntity.class, userModel.getId());
        List<AccessProofDetailEntity> drafts = em.createNamedQuery("getProofDetailsForUser", AccessProofDetailEntity.class)
                .setParameter("user", uEnt)
                .getResultList();

        Map<ChangeRequestKey, List<AccessProofDetailEntity>> grouped = drafts.stream()
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getChangeRequestKey));

        grouped.forEach((key, details) -> {
            try {
                // remove the envelope + drafts
                List<ChangesetRequestEntity> envelopes = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                        .setParameter("changesetRequestId", key.getChangeRequestId())
                        .getResultList();
                for (ChangesetRequestEntity cr : envelopes) {
                    cr.getAdminAuthorizations().clear();
                    em.remove(cr);
                }
                for (AccessProofDetailEntity pd : details) em.remove(pd);
                em.flush();

                // restage using original (user, client) + delta derived from stored draft/baseline
                List<UserContextDraftService.AffectedTuple> affected = new ArrayList<>();
                for (AccessProofDetailEntity pd : details) {
                    // pd.getUser() returns a JPA UserEntity; resolve models for rebuild
                    UserModel u = session.users().getUserById(realm, pd.getUser().getId());
                    // pd.getClientId() stores the DB ID; fetch by ID then expose logical clientId to stage()
                    ClientModel client = session.clients().getClientById(realm, pd.getClientId());
                    if (u == null || client == null) continue;

                    ObjectNode nowDefault = UserContextBuilder.build(session, realm, u, client);

                    String baselineJson = pd.getDefaultUserContext();
                    ObjectNode baseline = (baselineJson == null || baselineJson.isBlank())
                            ? nowDefault
                            : (ObjectNode) M.readTree(baselineJson);

                    Map<String, Object> delta = UserContextDeltaUtils.deriveDelta(baseline.toString(), pd.getProofDraft());

                    // Stage expects the logical clientId (alias), not the DB id
                    affected.add(new UserContextDraftService.AffectedTuple(u.getId(), client.getClientId(), delta));
                }

                if (!affected.isEmpty()) {
                    // ChangeSetType is on the entity row, not in ChangeRequestKey
                    ChangeSetType type = details.get(0).getChangesetType();

                    UserContextDraftService.stage(
                            session,
                            realm,
                            em,
                            key.getChangeRequestId(),
                            type,
                            affected,
                            null // authorizerPolicyHashBase64 if you precompute one for this request
                    );
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        em.flush();
    }

    // ---------- draft lookups (unchanged) ----------

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultList();
    }

    public static List<AccessProofDetailEntity> getUserContextDraftsForRealm(EntityManager em, String realmId) {
        return em.createNamedQuery("getProofDetailsForRealm", AccessProofDetailEntity.class)
                .setParameter("realmId", realmId)
                .getResultList();
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId, ChangeSetType changeSetType) {
        List<ChangeSetType> types = new ArrayList<>();
        if (changeSetType == ChangeSetType.COMPOSITE_ROLE || changeSetType == ChangeSetType.DEFAULT_ROLES) {
            types.add(ChangeSetType.DEFAULT_ROLES);
            types.add(ChangeSetType.COMPOSITE_ROLE);
        } else if (changeSetType == ChangeSetType.CLIENT_FULLSCOPE || changeSetType == ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT) {
            types.add(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT);
            types.add(ChangeSetType.CLIENT_FULLSCOPE);
        } else {
            types.add(changeSetType);
        }
        return em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .setParameter("changesetTypes", types)
                .getResultList();
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client) {
        return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                .setParameter("clientId", client.getId())
                .getResultList();
    }

    // ---------- role helpers (plain Keycloak only) ----------

    /** Expand composite roles using vanilla Keycloak utilities (no Tide adapters). */
    public static Set<RoleModel> expandCompositeRoles(Set<RoleModel> roles) {
        Set<RoleModel> visited = new HashSet<>();
        return roles.stream()
                .flatMap(r -> expandCompositeRolesStream(r, visited))
                .collect(Collectors.toSet());
    }

    /** Sometimes callers still want “all access” set given scopes/fullscope. */
    public static Set<RoleModel> getAllAccess(Set<RoleModel> roleModels,
                                              ClientModel client,
                                              Stream<ClientScopeModel> clientScopes,
                                              boolean isFullScopeAllowed,
                                              RoleModel roleToInclude) {
        Set<RoleModel> visited = new HashSet<>();
        Set<RoleModel> expanded = roleModels.stream()
                .flatMap(r -> expandCompositeRolesStream(r, visited))
                .collect(Collectors.toSet());

        if (roleToInclude != null) {
            expanded.add(roleToInclude);
        }

        if (isFullScopeAllowed) {
            return expanded;
        }

        Stream<RoleModel> scopeMappings = client.getRolesStream();
        Stream<RoleModel> clientScopesMappings = clientScopes.flatMap(ScopeContainerModel::getScopeMappingsStream);
        scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);
        scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

        expanded.retainAll(scopeMappings.collect(Collectors.toSet()));
        return expanded;
    }

    /** Filter by client scopes when fullscope is false. */
    public static Set<RoleModel> getAccess(Set<RoleModel> roleModels,
                                           ClientModel client,
                                           Stream<ClientScopeModel> clientScopes,
                                           boolean isFullScopeAllowed) {
        if (isFullScopeAllowed) return roleModels;

        Stream<RoleModel> scopeMappings = client.getRolesStream();
        Stream<ClientScopeModel> cs = (clientScopes == null) ? Stream.empty() : clientScopes;
        Stream<RoleModel> clientScopesMappings = cs.flatMap(ScopeContainerModel::getScopeMappingsStream);

        scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);
        scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

        roleModels.retainAll(scopeMappings.collect(Collectors.toSet()));
        return roleModels;
    }

    // ---------- internals ----------

    private static Stream<RoleModel> expandCompositeRolesStream(RoleModel role, Set<RoleModel> visited) {
        Stream.Builder<RoleModel> out = Stream.builder();
        if (!visited.add(role)) return out.build();

        Deque<RoleModel> stack = new ArrayDeque<>();
        stack.push(role);

        while (!stack.isEmpty()) {
            RoleModel cur = stack.pop();
            out.add(cur);
            if (cur.isComposite()) {
                cur.getCompositesStream()
                        .filter(r -> !visited.contains(r))
                        .forEach(r -> {
                            visited.add(r);
                            stack.push(r);
                        });
            }
        }
        return out.build();
    }

    // ---------- legacy mapping fetcher kept for old callers (unused by new engine) ----------

    @SuppressWarnings("unused")
    private Object getMappings(EntityManager em, String recordId, ChangeSetType type) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, recordId);
            case GROUP, USER_GROUP_MEMBERSHIP, GROUP_ROLE -> null;
            case COMPOSITE_ROLE, DEFAULT_ROLES -> em.find(TideCompositeRoleMappingDraftEntity.class, recordId);
            case ROLE -> em.find(TideRoleDraftEntity.class, recordId);
            case USER -> em.find(TideUserDraftEntity.class, recordId);
            case CLIENT_FULLSCOPE, CLIENT -> em.find(TideClientDraftEntity.class, recordId);
            default -> null;
        };
    }
}
