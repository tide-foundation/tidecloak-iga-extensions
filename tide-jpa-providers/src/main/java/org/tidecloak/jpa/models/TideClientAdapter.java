package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

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

        if ( entity.isFullScopeAllowed() || !draft.isEmpty()){
            return draft.get(0).getFullScopeEnabled() == DraftStatus.ACTIVE;
        }else{
            return false;
        }
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
        usersInRealm.forEach(x -> System.out.println(x.getUsername()));
        List<TideClientFullScopeStatusDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();
        if (usersInRealm.isEmpty() && statusDraft.isEmpty()) {
            createFullScopeStatusDraft(value, DraftStatus.ACTIVE);
            return;
        } else if (statusDraft.isEmpty() && value) {
            createFullScopeStatusDraft(value, DraftStatus.DRAFT);
            return;
        }
        TideClientFullScopeStatusDraftEntity clientFullScopeStatuses = statusDraft.get(0);
        if (value) {
            handleFullScopeEnabled(clientFullScopeStatuses, util, usersInRealm, client);
        } else {
            handleFullScopeDisabled(clientFullScopeStatuses, util, usersInRealm, client);
        }
    }
    private void createFullScopeStatusDraft(boolean value, DraftStatus draftStatus) {
        TideClientFullScopeStatusDraftEntity draft = new TideClientFullScopeStatusDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setClient(entity);
        if (value) {
            draft.setFullScopeEnabled(draftStatus);
        } else {
            draft.setFullScopeDisabled(draftStatus);
        }
        draft.setAction(ActionType.CREATE);
        em.persist(draft);
        em.flush();
    }
    private void handleFullScopeEnabled(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client) {
        if (clientFullScopeStatuses.getFullScopeEnabled() == DraftStatus.APPROVED) {
            approveFullScope(clientFullScopeStatuses, true);
        } else {
            startDraftApproval(clientFullScopeStatuses, util, usersInRealm, client, true);
        }
    }
    private void handleFullScopeDisabled(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client) {
        if (clientFullScopeStatuses.getFullScopeDisabled() == DraftStatus.APPROVED) {
            approveFullScope(clientFullScopeStatuses, false);
        } else {
            startDraftApproval(clientFullScopeStatuses, util, usersInRealm, client, false);
        }
    }
    private void approveFullScope(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, boolean isEnabled) {
        super.setFullScopeAllowed(isEnabled);
        if (isEnabled) {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
            clientFullScopeStatuses.setFullScopeDisabled(null);
        } else {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
            clientFullScopeStatuses.setFullScopeEnabled(null);
        }
        em.persist(clientFullScopeStatuses);
        em.flush();
    }
    private void startDraftApproval(TideClientFullScopeStatusDraftEntity clientFullScopeStatuses, TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, boolean enable) {
        if (enable && clientFullScopeStatuses.getFullScopeEnabled() == DraftStatus.ACTIVE) {
            return;
        } else if (!enable && clientFullScopeStatuses.getFullScopeDisabled() == DraftStatus.ACTIVE) {
            return;
        }
        if (enable) {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.DRAFT);
        } else {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.DRAFT);
        }
        em.persist(clientFullScopeStatuses);
        em.flush();
        if (enable) {
            createProofDraftsForUsers(util, usersInRealm, client, clientFullScopeStatuses.getId(), ActionType.CREATE, clientFullScopeStatuses);
        } else {
            regenerateAccessProofForUsers(util, usersInRealm, client, clientFullScopeStatuses.getId(), ActionType.DELETE, clientFullScopeStatuses);
        }
    }
    private void createProofDraftsForUsers(TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, String statusId, ActionType actionType, TideClientFullScopeStatusDraftEntity draft) {
        ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());

        usersInRealm.forEach(user -> {
            try {
                // Find any pending changes
                List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", draft.getId())
                        .getResultList();

                if(!pendingChanges.isEmpty()){
                    return;
                }
                UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.APPROVED, actionType);
                Set<RoleModel> roles = getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
                util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), tideUser, roles, statusId, ChangeSetType.CLIENT, actionType, true);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        });
    }
    private void regenerateAccessProofForUsers(TideAuthzProofUtil util, List<UserModel> usersInRealm, ClientModel client, String statusId, ActionType actionType, TideClientFullScopeStatusDraftEntity draft) {
        List<UserModel> usersInClient = new ArrayList<>();
        client.getRolesStream().forEach(role -> session.users().getRoleMembersStream(realm, role).forEach(user -> {
            if (!usersInClient.contains(user)) {
                usersInClient.add(user);
            }
        }));
        usersInRealm.forEach(user -> {
            ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());

            // Find any pending changes
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", draft.getId())
                    .getResultList();

            // if there is a pending change, we dont override
            if ( !pendingChanges.isEmpty()) {
                return;
            }
            try {
                UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE).stream().filter(role -> {
                    if (role.isClientRole()) {
                        return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                    }
                    return true;
                }).collect(Collectors.toSet());
                activeRoles.forEach(x -> System.out.println(x.getName()));
                util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), tideUser, activeRoles, statusId, ChangeSetType.CLIENT, actionType, true);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());

        // get all users who have this role for this client.
        List<UserModel> usersWithRole = new ArrayList<>();
        session.users().getRoleMembersStream(realm, role).forEach(user -> {
            if (!usersWithRole.contains(user)) {
                usersWithRole.add(user);
            }
        });

        super.deleteScopeMapping(role);

        proofGeneration.regenerateProofForClient(client, usersWithRole);

    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        ProtocolMapperModel protocolMapperModel = super.addProtocolMapper(model);

        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();

        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        proofGeneration.regenerateProofForClient(client, usersInClient);

        return protocolMapperModel;

    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();

        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        super.removeProtocolMapper(mapping);

        proofGeneration.regenerateProofForClient(client, usersInClient);

    }

    @Override
    public void updateProtocolMapper(ProtocolMapperModel mapping) {
        super.updateProtocolMapper(mapping);

        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();

        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        proofGeneration.regenerateProofForClient(client, usersInClient);
    }

    @Override
    public void addClientScopes(Set<ClientScopeModel> clientScopes, boolean defaultScope) {
        super.addClientScopes(clientScopes, defaultScope);
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();

        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        proofGeneration.regenerateProofForClient(client, usersInClient);
    }

    @Override
    public void removeClientScope(ClientScopeModel clientScope) {
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();

        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        super.removeClientScope(clientScope);

        proofGeneration.regenerateProofForClient(client, usersInClient);
    }

    @Override
    public void updateClient() {
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        session.getKeycloakSessionFactory().publish(new ClientModel.ClientUpdatedEvent() {

            @Override
            public ClientModel getUpdatedClient() {
                return TideClientAdapter.this;
            }

            @Override
            public KeycloakSession getKeycloakSession() {
                return session;
            }
        });

        ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
        Stream<RoleModel> rolesStream = client.getRolesStream();
        // get all users who have roles for this client.
        List<UserModel> usersInClient = new ArrayList<>();
        rolesStream.forEach(role -> {
            session.users().getRoleMembersStream(realm, role).forEach(user -> {
                if (!usersInClient.contains(user)) {
                    usersInClient.add(user);
                }
            });
        });

        proofGeneration.regenerateProofForClient(client, usersInClient);
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
