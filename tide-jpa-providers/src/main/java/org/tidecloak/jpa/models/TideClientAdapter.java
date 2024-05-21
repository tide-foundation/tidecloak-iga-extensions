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
        // Check if Status exist
        List<TideClientFullScopeStatusDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();


        // No users affected so we enable it.
        if(usersInRealm.isEmpty() || statusDraft.isEmpty()){
            TideClientFullScopeStatusDraftEntity draft = new TideClientFullScopeStatusDraftEntity();
            draft.setId(KeycloakModelUtils.generateId());
            draft.setClient(entity);
            if (!value){
                draft.setFullScopeDisabled(DraftStatus.ACTIVE); // full-scope disabled
            }else{
                draft.setFullScopeEnabled(DraftStatus.ACTIVE);
            }
            draft.setAction(ActionType.CREATE);
            em.persist(draft);
            em.flush();
            return;
        }

        System.out.println("WHAT IS THIS " + client.getName());

        // Check if Status exist
        TideClientFullScopeStatusDraftEntity clientFullScopeStatuses = statusDraft.get(0);

        if(value) {

            // If change was approved, we commit the changes and reset fullScopeDisableStatus back to null
            if ( clientFullScopeStatuses.getFullScopeEnabled() == DraftStatus.APPROVED){
                super.setFullScopeAllowed(true); // if approved, set the value to true
                clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE); // this is now active
                clientFullScopeStatuses.setFullScopeDisabled(null); // no longer track this
                em.persist(clientFullScopeStatuses);
                em.flush();
            }
            // If not approved, user is requesting to update client to full-scope so start draft approval chain
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.DRAFT);
            em.persist(clientFullScopeStatuses);
            em.flush();

            // We create a draft for approval if want fullscope to be enabled
            usersInRealm.forEach(user -> {
                UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE);
                Set<RoleModel> roles = getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);

                try {
                    util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), wrappedUser, roles, clientFullScopeStatuses.getId(), ChangeSetType.CLIENT, ActionType.CREATE); // cause we want to add roles in
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            });
        } else {

            // If change was approved, we commit the changes and reset fullScopeEnableStatus back to null
            if ( clientFullScopeStatuses.getFullScopeDisabled() == DraftStatus.APPROVED){
                super.setFullScopeAllowed(false); // if approved, set the value to true
                clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE); // this is now active
                clientFullScopeStatuses.setFullScopeEnabled(null); // no longer track this
                em.persist(clientFullScopeStatuses);
                em.flush();
            }

            // If not approved, user is requesting to update client to full-scope so start draft approval chain
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.DRAFT);
            em.persist(clientFullScopeStatuses);
            em.flush();

            // Get a list of users who have a access to this client
            Stream<RoleModel> rolesStream = client.getRolesStream();
            List<UserModel> usersInClient = new ArrayList<>();
            rolesStream.forEach(role -> {
                session.users().getRoleMembersStream(realm, role).forEach(user -> {
                    if (!usersInClient.contains(user)) {
                        usersInClient.add(user);
                    }
                });
            });

            // Get all users in the realm and check
            for( UserModel user : usersInRealm) {
                // need to regenerate the access proof for all users if they have a proof for this client
                List<UserClientAccessProofEntity> userFinalProof = em.createNamedQuery("getAccessProofByUserIdAndClientId", UserClientAccessProofEntity.class)
                        .setParameter("user", TideRolesUtil.toUserEntity(user, em))
                        .setParameter("clientId", entity.getId())
                        .getResultList();
                // check pending requests
                List<AccessProofDetailEntity> userDraftProof = em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                        .setParameter("user", TideRolesUtil.toUserEntity(user, em))
                        .setParameter("clientId", client.getId())
                        .getResultList();

                // user not affected
                if(userFinalProof.isEmpty() && userDraftProof.isEmpty()){
                    continue;
                }
                try {
                    UserModel tideUser = TideRolesUtil.wrapUserModel(user, session, realm);
                    // We only want to remove the roles that are not this clients role.
                    Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE).stream().filter(x -> {
                        if (x.isClientRole()){
                             return !Objects.equals(((ClientModel) x.getContainer()).getClientId(), client.getClientId());
                        }
                        return true;
                    }).collect(Collectors.toSet());

                    Set<RoleModel> roles = getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
                    UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                    util.generateAndSaveProofDraft(realm.getClientById(entity.getId()), wrappedUser, roles, clientFullScopeStatuses.getId(), ChangeSetType.CLIENT, ActionType.DELETE); // because we want to remove roles
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }

            };
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
