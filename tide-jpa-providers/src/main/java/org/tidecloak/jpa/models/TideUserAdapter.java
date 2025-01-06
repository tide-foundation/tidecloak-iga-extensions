package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;
import static org.tidecloak.jpa.utils.TideRolesUtil.wrapRoleModel;


public class TideUserAdapter extends UserAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;

    public TideUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        super(session, realm, em, user);
        this.session = session;
        this.realm = realm;
    }

    @Override
    public void joinGroup(GroupModel group) {
        super.joinGroup(group);
        TideUserGroupMembershipEntity entity = new TideUserGroupMembershipEntity();

        //TODO: !!!! CHECK IF THIS EXISTS BEFORE ADDING
        entity.setId(KeycloakModelUtils.generateId());
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        entity.setDraftStatus(DraftStatus.DRAFT);
        entity.setAction(ActionType.CREATE);
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    protected void joinGroupImpl(GroupModel group) {
        UserGroupMembershipEntity entity = new UserGroupMembershipEntity();
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        super.leaveGroup(group);
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(group);
        UserModel user = session.users().getUserById(realm, getEntity().getId());
        proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, List.of(user));
    }

    @Override
    public void grantRole(RoleModel roleModel) {
        RoleModel role = wrapRoleModel(roleModel, session, realm);
        RealmModel adminRealm = session.realms().getRealmByName(Config.getAdminRealm());

        if(session.users().getUsersCount(adminRealm) == 1 && Objects.equals(session.getContext().getRealm().getName(), adminRealm.getName())){
            super.grantRole(role);
            return;
        }
        super.grantRole(role);

        // Check if this has already been action before
        List<TideUserRoleMappingDraftEntity> entity =  em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusAndAction", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("actionType", ActionType.CREATE)
                .getResultList();

        // Add draft request
        if (entity == null || entity.isEmpty()) {
            // Create a draft record for new user role mapping
            TideUserRoleMappingDraftEntity draftUserRole = new TideUserRoleMappingDraftEntity();
            draftUserRole.setId(KeycloakModelUtils.generateId());
            draftUserRole.setRoleId(role.getId());
            draftUserRole.setUser(this.getEntity());
            draftUserRole.setAction(ActionType.CREATE);
            draftUserRole.setDraftStatus(DraftStatus.DRAFT);
            em.persist(draftUserRole);

            // Generate a proof draft for this changeset and any affected clients with full-scope enabled. These need to be signed.
            Set<RoleModel> roleMappings = new HashSet<>();
            roleMappings.add(role);
            // save the record for the user role grant
            List<ClientModel> clientList = getUniqueClientList(session, realm, role, em);

            UserModel user = session.users().getUserById(realm, getEntity().getId());
            UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
            if (role.isClientRole()
                    && ((ClientModel) role.getContainer()).getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID)) {

                clientList.forEach(client -> {
                    boolean isRealmManagementClient = client.getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
                    Set<RoleModel> rolesToUse = isRealmManagementClient ? roleMappings : Collections.emptySet();
                    boolean fullScopeAllowed = isRealmManagementClient && client.isFullScopeAllowed();

                    try {
                        util.generateAndSaveProofDraft(client, wrappedUser, rolesToUse, draftUserRole.getId(),
                                ChangeSetType.USER_ROLE, ActionType.CREATE, fullScopeAllowed);
                    } catch (Exception e) {
                        throw new RuntimeException("Error processing client: " + client.getClientId(), e);
                    }
                });

            } else {
                clientList.forEach(client -> {
                    try {
                        if (client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) || client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID)){
                            return;
                        }
                        util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draftUserRole.getId(),
                                ChangeSetType.USER_ROLE, ActionType.CREATE, client.isFullScopeAllowed());
                    } catch (Exception e) {
                        throw new RuntimeException("Error processing client: " + client.getClientId(), e);
                    }
                });
            }
            if(role.isComposite()){
                Set<TideRoleAdapter> wrappedRoles = roleMappings.stream().map(r -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, r.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                }).collect(Collectors.toSet());

                // we expand it and create a new record
                Set<RoleModel> compositeRoles = new HashSet<>();
                Set<RoleModel> draftCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles,DraftStatus.DRAFT);
                Set<RoleModel> pendingCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles,DraftStatus.PENDING);
                Set<RoleModel> approvedCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles,DraftStatus.APPROVED);
                Set<RoleModel> activeCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles,DraftStatus.ACTIVE);

                compositeRoles.addAll(draftCompositeRoles);
                compositeRoles.addAll(pendingCompositeRoles);
                compositeRoles.addAll(approvedCompositeRoles);
                compositeRoles.addAll(activeCompositeRoles);

                Set<RoleModel> uniqueCompositeRoles = compositeRoles.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());

                for(RoleModel r : uniqueCompositeRoles)
                {
                    if(Objects.equals(r.getId(), role.getId())){
                        continue;
                    }


                    RoleEntity compositeEntity = TideRolesUtil.toRoleEntity(realm.getRoleById(role.getId()), em);
                    RoleEntity childEntity = TideRolesUtil.toRoleEntity(r, em);

                    // Need to check if its committed yet, else just ignore
                    List<TideCompositeRoleMappingDraftEntity> compositeRoleMappingStatus = em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                            .setParameter("composite", compositeEntity)
                            .setParameter("childRole", childEntity)
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .getResultList();

                    if(compositeRoleMappingStatus == null || compositeRoleMappingStatus.isEmpty()){
                        continue;
                    }

                    Set<RoleModel> roleSet = new HashSet<>();
                    roleSet.add(r);
                    roleSet.add(role);
                    try {
                        ClientModel childRoleClient = session.clients().getClientByClientId(realm, childEntity.getClientId());
                        if(childRoleClient != null){
                            // Add proof record for Child Role
                            util.generateAndSaveProofDraft(childRoleClient, wrappedUser, roleSet, compositeRoleMappingStatus.get(0).getChildRole().getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, childRoleClient.isFullScopeAllowed());
                        }

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
            em.flush();
        }
    }


    @Override
    public void deleteRoleMapping(RoleModel roleModel) {
        RoleModel role = wrapRoleModel(roleModel, session, realm);

        String igaAttribute = session.getContext().getRealm().getAttribute("isIGAEnabled");
        boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

        if (!isIGAEnabled){
            List<TideUserRoleMappingDraftEntity> draftEntities = getDraftEntities(role);
            deleteRoleAndProofRecords(role, draftEntities);
            return;
        }

        List<TideUserRoleMappingDraftEntity> activeDraftEntities = getActiveDraftEntities(role);

        if (activeDraftEntities.isEmpty()) {
            deleteRoleAndProofRecords(role, activeDraftEntities);
            return;
        }

        TideUserRoleMappingDraftEntity committedEntity = activeDraftEntities.get(0);
        if (committedEntity.getDeleteStatus() == DraftStatus.ACTIVE) {
            deleteRoleAndProofRecords(role, activeDraftEntities);
            return;
        }

        markForDeletion(activeDraftEntities);
        generateProofDrafts(role, activeDraftEntities);
        em.flush();
    }

    private List<TideUserRoleMappingDraftEntity> getActiveDraftEntities(RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();
    }
    private List<TideUserRoleMappingDraftEntity> getDraftEntities(RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .getResultList();
    }

    private List<ClientModel> getUniqueClientList(KeycloakSession session, RealmModel realm, RoleModel role, EntityManager em) {
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        if ( role.isClientRole()){
            clientList.add((ClientModel) role.getContainer());
        }

        // need to expand role and get the clientlist here too
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        Set<TideRoleAdapter> wrappedRoles = new HashSet<>();
        wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));

        Set<RoleModel> activeCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles,DraftStatus.ACTIVE);

        activeCompositeRoles.forEach(activeCompRole -> {
            if (activeCompRole.getContainer() instanceof ClientModel){
                clientList.add((ClientModel) activeCompRole.getContainer());
            }
        });

        return clientList.stream().distinct().collect(Collectors.toList());
    }

    private void deleteRoleAndProofRecords(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        String recordId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? getDraftEntities(role).get(0).getId() : activeDraftEntities.get(0).getId();
        deleteProofRecordForUser(recordId);
        deleteUserRoleMappingDraftsByRole(role.getId());

        if (role.isComposite()) {
            deleteCompositeRoleProofRecords(role);
        }
        super.deleteRoleMapping(role);
    }

    private void deleteUserRoleMappingDraftsByRole(String roleId) {
        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", roleId)
                .executeUpdate();
    }

    private void deleteProofRecordForUser(String recordId) {
        em.createNamedQuery("deleteProofRecordForUser")
                .setParameter("recordId", recordId)
                .setParameter("user", getEntity())
                .executeUpdate();
    }

    private void deleteCompositeRoleProofRecords(RoleModel role) {
        List<AccessProofDetailEntity> proofRecords = em.createNamedQuery("FindUserWithCompositeRoleRecord", AccessProofDetailEntity.class)
                .setParameter("composite", TideRolesUtil.toRoleEntity(role, em))
                .setParameter("user", getEntity())
                .getResultList();
        proofRecords.forEach(em::remove);
    }

    private void markForDeletion(List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        if (activeDraftEntities != null && !activeDraftEntities.isEmpty()) {
            TideUserRoleMappingDraftEntity userRoleMapping = activeDraftEntities.get(0);
            userRoleMapping.setDeleteStatus(DraftStatus.DRAFT);
            userRoleMapping.setTimestamp(System.currentTimeMillis());
        }
    }

    private void generateProofDrafts(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        if (role.getContainer() instanceof ClientModel) {
            List<ClientModel> clientList = getUniqueClientList(session, realm, role, em);

            UserModel user = session.users().getUserById(realm, getEntity().getId());
            UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

            clientList.forEach(client -> generateProofDraftForClient(role, client, wrappedUser, util, activeDraftEntities));
        }
    }

    private void generateProofDraftForClient(RoleModel role, ClientModel client, UserModel wrappedUser, TideAuthzProofUtil util, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        Set<RoleModel> roleMappings = new HashSet<>();
        roleMappings.add(role);
        try {
            String draftId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? role.getId() : activeDraftEntities.get(0).getId();
            util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draftId,
                    ChangeSetType.USER_ROLE, ActionType.DELETE, client.isFullScopeAllowed());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        // we query ids only as the role might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        TypedQuery<String> query = em.createNamedQuery("userRoleMappingIds", String.class);
        query.setParameter("user", getEntity());
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

    public Stream<RoleModel> getRoleMappingsStreamByStatusAndAction(DraftStatus status, ActionType actionType) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityIdsByStatusAndAction", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        query.setParameter("actionType", actionType);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

    public Stream<RoleModel> getRoleMappingsStreamByStatus(DraftStatus status) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityIdsByStatus", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }


}