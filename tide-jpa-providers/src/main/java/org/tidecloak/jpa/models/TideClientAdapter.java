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
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Stream;

public class TideClientAdapter extends ClientAdapter {

    public TideClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity entity) {
        super(realm, em, session, entity);
    }

    @Override
    public boolean isFullScopeAllowed() {
        List<TideClientFullScopeStatusDraftEntity> draft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();

        if (entity.isFullScopeAllowed()){
            // check if there are any pending requests for fullscope changes
            return draft.isEmpty() || draft.get(0).getDraftStatus() == DraftStatus.APPROVED;
        }else{
            return false;
        }
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        System.out.println("HELLO I AM HERE IN SETTING FULLSCOPE");
        super.setFullScopeAllowed(value);
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        Set<RoleModel> roleMappings = new HashSet<>();

        if(value){
            List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
            if(usersInRealm.isEmpty()){
                return;
            }
            TideClientFullScopeStatusDraftEntity clientDraftEntity = new TideClientFullScopeStatusDraftEntity();
            clientDraftEntity.setId(KeycloakModelUtils.generateId());
            clientDraftEntity.setClient(entity);
            clientDraftEntity.setDraftStatus(DraftStatus.DRAFT);
            clientDraftEntity.setAction(ActionType.CREATE);
            em.persist(clientDraftEntity);
            em.flush();

            usersInRealm.forEach(user -> {
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);

                try {
                    util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), wrappedUser, roleMappings, clientDraftEntity.getId(), ChangeSetType.CLIENT, ActionType.CREATE);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            });
        } else {
            ClientModel client = session.clients().getClientByClientId(realm, entity.getClientId());
            Stream<RoleModel> rolesStream = client.getRolesStream();
            List<UserModel> usersInClient = new ArrayList<>();
            rolesStream.forEach(role -> {
                session.users().getRoleMembersStream(realm, role).forEach(user -> {
                    if (!usersInClient.contains(user)) {
                        usersInClient.add(user);
                    }
                });
            });
            if (usersInClient.isEmpty()){
                return;
            }
            TideClientFullScopeStatusDraftEntity clientDraftEntity = new TideClientFullScopeStatusDraftEntity();
            clientDraftEntity.setId(KeycloakModelUtils.generateId());
            clientDraftEntity.setClient(entity);
            clientDraftEntity.setDraftStatus(DraftStatus.DRAFT);
            clientDraftEntity.setAction(ActionType.CREATE);
            em.persist(clientDraftEntity);
            em.flush();

            usersInClient.forEach(user -> {
                try {
                    UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                    util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), wrappedUser, roleMappings, clientDraftEntity.getId(), ChangeSetType.CLIENT, ActionType.CREATE);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            });
        }
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
