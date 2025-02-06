package org.tidecloak.iga.changesetprocessors.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.keycloak.authorization.policy.evaluation.Realm;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.midgard.Serialization.JsonSorter;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.utils.UserContextUtilBase;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UserContextUtils extends UserContextUtilBase {

    public void recreateUserContext(KeycloakSession session, UserModel userModel) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // get all affected clients from AccessProofDraftEntity
        // This returns the access proof in descending order by timestamp
        UserEntity user = em.find(UserEntity.class, userModel.getId());

        List<AccessProofDetailEntity> userAccessDrafts = em.createNamedQuery("getProofDetailsForUser", AccessProofDetailEntity.class)
                .setParameter("user", user)
                .getResultStream()
                .toList();

        Map<String, List<AccessProofDetailEntity>> groupedProofDetails = userAccessDrafts.stream()
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getRecordId));

        groupedProofDetails.forEach((changeRequestId, details)  -> {
            try {
                // remove old request, then we recreate
                List<ChangesetRequestEntity> changesetRequestEntity = em.createNamedQuery("ChangesetRequestEntity", ChangesetRequestEntity.class).setParameter("changesetRequestId", changeRequestId).getResultList();
                if(!changesetRequestEntity.isEmpty()) {
                    changesetRequestEntity.forEach(em::remove);
                }
                em.flush();


                ChangeSetType changeSetType = details.get(0).getChangesetType();
                ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();
                WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, changeSetType);
                Object mapping = getMappings(em, changeRequestId, changeSetType);
                changeSetProcessorFactory.getProcessor(changeSetType).executeWorkflow(session, mapping, em, WorkflowType.REQUEST, params, null);

                details.forEach(em::remove);
                em.flush();

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    @Override
    public  Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        UserEntity userEntity = TideEntityUtils.toUserEntity(user, em);
        TideUserAdapter tideUser = TideEntityUtils.toTideUserAdapter( userEntity, session, realm);

        Set<RoleModel> roleMappings = tideUser.getRoleMappingsStreamByStatus(draftStatus).map((x) -> TideEntityUtils.wrapRoleModel(x, session, realm)).collect(Collectors.toSet());

        user.getGroupsStream().forEach((group) -> {
            TideEntityUtils.addGroupRoles(TideEntityUtils.wrapGroupModel(group, session, realm), roleMappings, draftStatus);
        });
        Set<RoleModel> wrappedRoles = roleMappings.stream().map((r) -> (TideRoleAdapter) TideEntityUtils.wrapRoleModel(r, session, realm)).collect(Collectors.toSet());
        return expandCompositeRoles(wrappedRoles, draftStatus);
    }


    @Override
    public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
        RealmModel realm = session.getContext().getRealm();

        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(TideEntityUtils.toTideRoleAdapter(roleModel, session, realm), visited, DraftStatus.ACTIVE))
                .collect(Collectors.toSet());
    }


    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId, ChangeSetType changeSetType) {
        return em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .setParameter("changesetType", changeSetType)
                .getResultStream()
                .collect(Collectors.toList());
    }


    public static List<AccessProofDetailEntity>  getUserContextDrafts(EntityManager em, ClientModel client) {
        return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                .setParameter("clientId", client.getId())
                .getResultList();
    }

    public static Set<RoleModel> expandCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
        RealmModel realm = session.getContext().getRealm();

        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(TideEntityUtils.toTideRoleAdapter(roleModel, session, realm), visited, DraftStatus.ACTIVE))
                .collect(Collectors.toSet());
    }

    public static Set<RoleModel> getAllAccess(KeycloakSession session, Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes, boolean isFullScopeAllowed, RoleModel roleToInclude) {
        RealmModel realm = session.getContext().getRealm();

        Set<RoleModel> visited = new HashSet<>();

        Set<RoleModel> expanded = roleModels.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(TideEntityUtils.toTideRoleAdapter(roleModel, session, realm), visited, DraftStatus.ACTIVE))
                .collect(Collectors.toSet());

        if ( roleToInclude != null) {
            expanded.add(roleToInclude);
        }

        if (isFullScopeAllowed) {
            return expanded;
        } else {

            // 1 - Client roles of this client itself
            Stream<RoleModel> scopeMappings = client.getRolesStream();

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            Stream<RoleModel> clientScopesMappings;
            clientScopesMappings = clientScopes.flatMap(ScopeContainerModel::getScopeMappingsStream);

            scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);

            // 3 - Expand scope mappings
            scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings
            expanded.retainAll(scopeMappings.collect(Collectors.toSet()));

            return expanded;
        }
    }


    public static Set<RoleModel> getAccess(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes, boolean isFullScopeAllowed) {
        if (isFullScopeAllowed) {
            return roleModels;
        } else {

            // 1 - Client roles of this client itself
            Stream<RoleModel> scopeMappings = client.getRolesStream();

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            Stream<RoleModel> clientScopesMappings;
            clientScopesMappings = clientScopes.flatMap(ScopeContainerModel::getScopeMappingsStream);

            scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);

            // 3 - Expand scope mappings
            scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings
            roleModels.retainAll(scopeMappings.collect(Collectors.toSet()));

            return roleModels;
        }
    }

    public static void addRoleToAccessTokenMasterRealm(AccessToken token, RoleModel role, RealmModel realm, EntityManager em) {
        AccessToken.Access access = null;
        if (!role.isClientRole()) {
            // Handle realm-level roles
            access = token.getRealmAccess();
            if (access == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            }

            // Check for duplicates first
            if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        } else if (role.isClientRole()) {
            RoleEntity roleEntity = em.find(RoleEntity.class, role.getId());
            ClientModel client = realm.getClientById(roleEntity.getClientId());
            // Handle client-level roles
            access = token.getResourceAccess(client.getClientId());

            if (access == null) {
                access = token.addAccess(client.getClientId());
                if (client.isSurrogateAuthRequired()) {
                    access.verifyCaller(true);
                }
            } else if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        }
    }

    public static void addRoleToAccessToken(AccessToken token, RoleModel role) {
        AccessToken.Access access = null;

        if (role.getContainer() instanceof RealmModel) {
            // Handle realm-level roles
            access = token.getRealmAccess();
            if (access == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            }

            // Check for duplicates first
            if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        } else if (role.getContainer() instanceof ClientModel client) {

            // Handle client-level roles
            access = token.getResourceAccess(client.getClientId());

            if (access == null) {
                access = token.addAccess(client.getClientId());
                if (client.isSurrogateAuthRequired()) {
                    access.verifyCaller(true);
                }
            } else if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        }
    }

    public static void removeRoleFromAccessTokenMasterRealm(AccessToken token, RoleModel role, RealmModel realm, EntityManager em) {
        if (!role.isClientRole()) {
            // Handle realm-level roles
            AccessToken.Access realmAccess = token.getRealmAccess();
            if (realmAccess != null && realmAccess.getRoles().contains(role.getName())) {
                realmAccess.getRoles().remove(role.getName());
            }
        } else if (role.isClientRole()) {
            // Handle client-level roles
            RoleEntity roleEntity = em.find(RoleEntity.class, role.getId());
            ClientModel client = realm.getClientById(roleEntity.getClientId());
            AccessToken.Access clientAccess = token.getResourceAccess(client.getClientId());
            if (clientAccess != null && clientAccess.getRoles().contains(role.getName())) {
                clientAccess.getRoles().remove(role.getName());
            }
        }
    }


    public static void removeRoleFromAccessToken(AccessToken token, RoleModel role) {
        if (role.getContainer() instanceof RealmModel) {
            // Handle realm-level roles
            AccessToken.Access realmAccess = token.getRealmAccess();
            if (realmAccess != null && realmAccess.getRoles().contains(role.getName())) {
                realmAccess.getRoles().remove(role.getName());
            }
        } else if (role.getContainer() instanceof ClientModel) {
            // Handle client-level roles
            ClientModel client = (ClientModel) role.getContainer();
            AccessToken.Access clientAccess = token.getResourceAccess(client.getClientId());
            if (clientAccess != null && clientAccess.getRoles().contains(role.getName())) {
                clientAccess.getRoles().remove(role.getName());
            }
        }
    }

    public void normalizeAccessToken(AccessToken token, boolean isFullscope){
        updateTokenAudience(token, isFullscope);
        cleanAccessToken(token);
    }

    public static void updateTokenAudience(AccessToken token, boolean isFullscope) {
        if(!isFullscope){
            token.audience(null);
            return;
        }
        // Create a set to hold the updated audience
        Set<String> audience = new HashSet<>();

        // Add clients from resource access that still have roles
        Map<String, AccessToken.Access> resourceAccess = token.getResourceAccess();
        if (resourceAccess != null) {
            resourceAccess.forEach((clientId, access) -> {
                if (access != null && access.getRoles() != null && !access.getRoles().isEmpty()) {
                    audience.add(clientId); // Include only clients with roles
                }
            });
        }

        // Update the token audience or remove it if empty
        if (audience.isEmpty()) {
            token.audience(null); // Remove the audience field
        } else {
            token.audience(audience.toArray(new String[0])); // Update the audience with filtered clients
        }
    }


    public static void cleanAccessToken(AccessToken token) {
        // Clean up realm access if roles are empty or null
        if (token.getRealmAccess() != null &&
                (token.getRealmAccess().getRoles() == null || token.getRealmAccess().getRoles().isEmpty())) {
            token.setRealmAccess(null);
        }

        // Clean up resource access
        if (token.getResourceAccess() != null) {
            Map<String, AccessToken.Access> resourceAccess = token.getResourceAccess();
            resourceAccess.entrySet().removeIf(entry ->
                    entry.getValue().getRoles() == null || entry.getValue().getRoles().isEmpty()
            );
            // If no resource access remains, remove the map entirely
            if (resourceAccess.isEmpty()) {
                token.setResourceAccess(null);
            }
        }
    }



    private Set<RoleModel> expandCompositeRoles(Set<RoleModel> roles, DraftStatus draftStatus) {
        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(roleModel, visited, draftStatus))
                .collect(Collectors.toSet());
    }


    /**
     * Recursively expands composite roles into their composite.
     *
     * @param role
     * @param visited Track roles, which were already visited. Those will be ignored and won't be added to the stream. Besides that,
     *                the "visited" set itself will be updated as a result of this method call and all the tracked roles will be added to it
     * @return Stream of containing all of the composite roles and their components. Never returns {@code null}.
     */
    private static Stream<RoleModel> expandCompositeRolesStream(RoleModel role, Set<RoleModel> visited, DraftStatus draftStatus) {
        Stream.Builder<RoleModel> sb = Stream.builder();

        if (!visited.add(role)) {
            return sb.build(); // Early return if role is already visited
        }

        Deque<RoleModel> stack = new ArrayDeque<>();
        //TODO: if initial role is pending a delete, we do not bother expanding it.

        stack.push(role);


        while (!stack.isEmpty()) {
            RoleModel current = stack.pop();
            sb.add(current);

            if (current.isComposite()) {
                Stream<RoleModel> compositesStream;

                // Check if the role can be cast to CustomRoleAdapter and has the method
                if (role instanceof TideRoleAdapter) {
                    compositesStream = ((TideRoleAdapter) current).getCompositesStreamByStatus(draftStatus);
                } else {
                    // Fallback to default composites if not a CustomRoleAdapter
                    compositesStream = current.getCompositesStream();
                }

                compositesStream
                        .filter(r -> !visited.contains(r))
                        .forEach(r -> {
                            visited.add(r);
                            stack.push(r);
                        });
            }
        }

        return sb.build();
    }

    private Object getMappings(EntityManager em, String recordId, ChangeSetType type) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, recordId);
            case GROUP, USER_GROUP_MEMBERSHIP, GROUP_ROLE -> null;
            case COMPOSITE_ROLE, DEFAULT_ROLES -> em.find(TideCompositeRoleMappingDraftEntity.class, recordId);
            case ROLE -> em.find(TideRoleDraftEntity.class, recordId);
            case USER -> em.find(TideUserDraftEntity.class, recordId);
            case CLIENT_FULLSCOPE -> em.find(TideClientDraftEntity.class, recordId);
            default -> null;
        };
    }



}
