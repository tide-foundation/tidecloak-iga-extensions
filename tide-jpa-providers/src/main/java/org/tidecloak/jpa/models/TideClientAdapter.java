package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftChangeSetRequest;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.IGAUtils;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.Protocol.mapper.TideRolesProtocolMapper.getAccess;

public class TideClientAdapter extends ClientAdapter {

    public TideClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity entity) {
        super(realm, em, session, entity);
    }

    @Override
    public boolean isFullScopeAllowed() {

        List<TideClientFullScopeStatusDraftEntity> draft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();

        return entity.isFullScopeAllowed() || (draft != null && !draft.isEmpty() && draft.get(0).getFullScopeEnabled() == DraftStatus.ACTIVE);
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
        List<TideClientFullScopeStatusDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();

        // if no users and no drafts
        if (usersInRealm.isEmpty() && statusDraft.isEmpty()) {
            createFullScopeStatusDraft(value);
            super.setFullScopeAllowed(value);
            return;
        }

        // if theres users and no drafts
        else if (!usersInRealm.isEmpty() && statusDraft.isEmpty()) {
            createFullScopeStatusDraft(false); // New clients defaults to restricted scope if there are users in the realm.
            return;
        }
        TideClientFullScopeStatusDraftEntity clientFullScopeStatuses = statusDraft.get(0);
        try{
            if (value) {
                handleFullScopeEnabled(clientFullScopeStatuses, util, usersInRealm, client);

            } else {
                handleFullScopeDisabled(clientFullScopeStatuses, util, usersInRealm, client);
            }

        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
    private void createFullScopeStatusDraft(boolean value) {
        TideClientFullScopeStatusDraftEntity draft = new TideClientFullScopeStatusDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setClient(entity);
        if (value) {
            draft.setFullScopeEnabled(DraftStatus.ACTIVE);
            draft.setFullScopeDisabled(DraftStatus.NULL);
        } else {
            draft.setFullScopeDisabled(DraftStatus.ACTIVE);
            draft.setFullScopeEnabled(DraftStatus.NULL);
        }
        draft.setAction(ActionType.CREATE);
        em.persist(draft);
        em.flush();
    }
    private void handleFullScopeEnabled(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client) throws NoSuchAlgorithmException, JsonProcessingException {
        if (clientFullScopeStatuses.getFullScopeEnabled() == DraftStatus.APPROVED) {
            approveFullScope(clientFullScopeStatuses, true);
        }
        else if (clientFullScopeStatuses.getFullScopeEnabled() == DraftStatus.ACTIVE){
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", clientFullScopeStatuses.getId())
                    .getResultList();

            if (!pendingChanges.isEmpty()) {
                em.remove(pendingChanges.get(0));
                em.flush();
            }
        }
        else {
            startDraftApproval(clientFullScopeStatuses, util, usersInRealm, client, true);
        }
    }
    private void handleFullScopeDisabled(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client) throws NoSuchAlgorithmException, JsonProcessingException {
        if (clientFullScopeStatuses.getFullScopeDisabled() == DraftStatus.APPROVED) {
            approveFullScope(clientFullScopeStatuses, false);
        }
        else if (clientFullScopeStatuses.getFullScopeDisabled() == DraftStatus.ACTIVE){
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", clientFullScopeStatuses.getId())
                    .getResultList();

            if (!pendingChanges.isEmpty()) {
                em.remove(pendingChanges.get(0));
                em.flush();
            }
        }
        else {
            startDraftApproval(clientFullScopeStatuses, util, usersInRealm, client, false);
        }
    }
    private void approveFullScope(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, boolean isEnabled) {
        if (isEnabled) {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
            em.persist(clientFullScopeStatuses);
        } else {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
            em.persist(clientFullScopeStatuses);
        }
        super.setFullScopeAllowed(isEnabled);
        em.flush();

    }
    private void startDraftApproval(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, boolean enable) throws NoSuchAlgorithmException, JsonProcessingException {
        if (enable) {
            createProofDraftsForUsers(util, usersInRealm, client, clientFullScopeStatuses.getId(), clientFullScopeStatuses);
        } else {
            regenerateAccessProofForUsers(util, usersInRealm, client, clientFullScopeStatuses.getId(), clientFullScopeStatuses);
        }
    }
    private void createProofDraftsForUsers(TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, String statusId, TideClientFullScopeStatusDraftEntity draft) {
        draft.setFullScopeEnabled(DraftStatus.DRAFT);
        em.persist(draft);
        em.flush();
        usersInRealm.forEach(user -> {
            try {
                // Find any pending changes
                List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", draft.getId())
                        .getResultList();

                if(pendingChanges != null && !pendingChanges.isEmpty()){
                    return;
                }
                UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.ACTIVE);
                Set<RoleModel> roles = getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
                util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), tideUser, roles, statusId, ChangeSetType.CLIENT, ActionType.CREATE, true);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        });
    }
    private void regenerateAccessProofForUsers(TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, String statusId, TideClientFullScopeStatusDraftEntity draft) throws NoSuchAlgorithmException, JsonProcessingException {
        List<UserModel> usersInClient = new ArrayList<>();
        client.getRolesStream().forEach(role -> session.users().getRoleMembersStream(realm, role).forEach(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", role.getId())
                    .getResultList();

            if (userRecords != null && !userRecords.isEmpty() && !usersInClient.contains(user)) {
                usersInClient.add(user);
            }
        }));
        if(usersInClient.isEmpty()){
            super.setFullScopeAllowed(false);
            approveFullScope(draft, false);
            DraftChangeSetRequest draftChangeSetRequest = new DraftChangeSetRequest();
            draftChangeSetRequest.setType(ChangeSetType.CLIENT);
            draftChangeSetRequest.setActionType(ActionType.DELETE);
            draftChangeSetRequest.setChangeSetId(draft.getId());

            util.checkAndUpdateProofRecords(draftChangeSetRequest, draft, ChangeSetType.CLIENT, em);
            return;
        }

        draft.setFullScopeDisabled(DraftStatus.DRAFT);
        em.persist(draft);
        em.flush();

        usersInClient.forEach(user -> {
            // Find any pending changes
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", draft.getId())
                    .getResultList();

            if ( pendingChanges != null && !pendingChanges.isEmpty()) {
                return;
            }
            try {
                UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.ACTIVE).stream().filter(role -> {
                    if (role.isClientRole()) {
                        return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                    }
                    return true;
                }).collect(Collectors.toSet());
                util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), tideUser, activeRoles, statusId, ChangeSetType.CLIENT, ActionType.DELETE, true);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        return super.addProtocolMapper(model);

    }

    @Override
    public RoleModel addRole(String name) {
        return session.roles().addClientRole(this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return session.roles().addClientRole(this, id, name);
    }

}