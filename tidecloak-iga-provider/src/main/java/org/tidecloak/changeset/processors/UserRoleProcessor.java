package org.tidecloak.changeset.processors;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.tidecloak.changeset.utils.ClientUtils;
import org.tidecloak.changeset.utils.TideEntityUtils;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.enums.ActionType;


import java.util.*;
import java.util.stream.Collectors;

public class UserRoleProcessor implements ChangeSetProcessor<TideUserRoleMappingDraftEntity> {

    @Override
    public void request(KeycloakSession session, ChangeSetRequest change, TideUserRoleMappingDraftEntity mapping, EntityManager em, ActionType action) {
        try {
            // Handle action types (CREATE, UPDATE, DELETE)
            switch (action) {
                case CREATE:
                    handleCreateRequest(session, mapping, em);
                    break;
                case DELETE:
                    handleDeleteRequest(session, mapping, em);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            System.out.println("Successfully processed USER_ROLE with ID: " + mapping.getId());

        } catch (Exception e) {
            System.err.println("Error processing USER_ROLE: " + e.getMessage());
            throw new RuntimeException("Failed to process USER_ROLE mapping", e);
        }
    }


    @Override
    public void updateAffectedChangeRequests(ChangeSetRequest change, TideUserRoleMappingDraftEntity entity, ChangeSetType changeSetType, EntityManager em, KeycloakSession session, RealmModel realm) {

    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserRoleMappingDraftEntity mapping, EntityManager em) {
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        UserModel userModel = TideEntityUtils.toTideUserAdapter(mapping.getUser(), session, realm);

        Set<RoleModel> roleMappings = Collections.singleton(role);
        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

        if (role.isClientRole() && isRealmManagementClient(role)) {
            processRealmManagementRoleAssignment(session, em, realm, clientList, roleMappings, mapping, userModel);
        } else {
            processRoles(session, em, realm, clientList, roleMappings, mapping, userModel);
        }

        if (role.isComposite()) {
            processCompositeRoles(session, em, realm, roleMappings, role, userModel);
        }

        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserRoleMappingDraftEntity mapping, EntityManager em) {
        RealmModel realm = session.getContext().getRealm();
        RoleEntity roleEntity = em.find(RoleEntity.class, mapping.getRoleId());
        RoleModel tideRoleModel = TideEntityUtils.toTideRoleAdapter(roleEntity, session, realm);
        List<TideUserRoleMappingDraftEntity> activeDraftEntities = TideUserAdapter.getActiveDraftEntities(em, mapping.getUser(), tideRoleModel);


        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, tideRoleModel, em);

        UserModel wrappedUser = TideEntityUtils.toTideUserAdapter(mapping.getUser(), session, realm);

        Set<RoleModel> roleMappings = new HashSet<>();
        roleMappings.add(tideRoleModel);

        clientList.forEach(client -> {
            try {
                String draftId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? mapping.getRoleId() : activeDraftEntities.getFirst().getId();
                this.generateAndSaveUserContextDraft(session, em, realm, client, wrappedUser, roleMappings, draftId,
                        ChangeSetType.USER_ROLE, ActionType.DELETE, client.isFullScopeAllowed());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // Helper Methods
    private boolean isRealmManagementClient(RoleModel role) {
        return ((ClientModel) role.getContainer()).getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
    }

    private void processRealmManagementRoleAssignment(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                      Set<RoleModel> roleMappings, TideUserRoleMappingDraftEntity mapping, UserModel userModel) {
        clientList.forEach(client -> {
            try {
                boolean isRealmManagementClient = client.getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
                Set<RoleModel> rolesToUse = isRealmManagementClient ? roleMappings : Collections.emptySet();
                boolean fullScopeAllowed = isRealmManagementClient && client.isFullScopeAllowed();

                this.generateAndSaveUserContextDraft(session, em, realm, client, userModel, rolesToUse, mapping.getId(),
                        ChangeSetType.USER_ROLE, ActionType.CREATE, fullScopeAllowed);
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private void processRoles(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                  Set<RoleModel> roleMappings, TideUserRoleMappingDraftEntity mapping, UserModel userModel) {
        clientList.forEach(client -> {
            try {
                if (isAdminClient(client)) {
                    return;
                }
                this.generateAndSaveUserContextDraft(session, em, realm, client, userModel, roleMappings, mapping.getId(),
                        ChangeSetType.USER_ROLE, ActionType.CREATE, client.isFullScopeAllowed());
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private boolean isAdminClient(ClientModel client) {
        return client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) ||
                client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID);
    }

    private void processCompositeRoles(KeycloakSession session, EntityManager em, RealmModel realm,
                                       Set<RoleModel> roleMappings, RoleModel role, UserModel userModel) {
        Set<TideRoleAdapter> wrappedRoles = wrapRolesAsTideAdapters(roleMappings, session, realm, em);
        Set<RoleModel> uniqueCompositeRoles = expandAllCompositeRoles(wrappedRoles);

        uniqueCompositeRoles.forEach(r -> {
            if (Objects.equals(r.getId(), role.getId())) {
                return; // Skip the same role
            }
            processCompositeRoleMapping(session, em, realm, r, role, userModel);
        });
    }

    private Set<TideRoleAdapter> wrapRolesAsTideAdapters(Set<RoleModel> roles, KeycloakSession session, RealmModel realm, EntityManager em) {
        return roles.stream()
                .map(r -> new TideRoleAdapter(session, realm, em, em.getReference(RoleEntity.class, r.getId())))
                .collect(Collectors.toSet());
    }

    private Set<RoleModel> expandAllCompositeRoles(Set<TideRoleAdapter> wrappedRoles) {
        Set<RoleModel> compositeRoles = new HashSet<>();
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.DRAFT));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.PENDING));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.APPROVED));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE));

        return compositeRoles.stream().filter(Objects::nonNull).collect(Collectors.toSet());
    }

    private void processCompositeRoleMapping(KeycloakSession session, EntityManager em, RealmModel realm, RoleModel childRole,
                                             RoleModel parentRole, UserModel userModel) {
        RoleEntity parentEntity = TideEntityUtils.toRoleEntity(parentRole, em);
        RoleEntity childEntity = TideEntityUtils.toRoleEntity(childRole, em);

        // Query to check if the composite role mapping is active
        List<TideCompositeRoleMappingDraftEntity> compositeRoleMappingStatus = em.createNamedQuery(
                        "getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", parentEntity)
                .setParameter("childRole", childEntity)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();

        // Skip if no active composite role mapping exists
        if (compositeRoleMappingStatus == null || compositeRoleMappingStatus.isEmpty()) {
            return;
        }

        try {
            ClientModel childRoleClient = session.clients().getClientByClientId(realm, childEntity.getClientId());

            if (childRoleClient != null) {
                // Prepare a set of roles (parent and child)
                Set<RoleModel> roleSet = new HashSet<>();
                roleSet.add(parentRole);
                roleSet.add(childRole);

                // Generate and save a user context draft for the composite role
                this.generateAndSaveUserContextDraft(
                        session,
                        em,
                        realm,
                        childRoleClient,
                        userModel,
                        roleSet,
                        compositeRoleMappingStatus.getFirst().getChildRole().getId(),
                        ChangeSetType.COMPOSITE_ROLE,
                        ActionType.CREATE,
                        childRoleClient.isFullScopeAllowed()
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Error processing composite role mapping for childRole: " + childRole.getName(), e);
        }
    }

}