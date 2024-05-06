package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

public class TideClientAdapter extends ClientAdapter {

    public TideClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity entity) {
        super(realm, em, session, entity);
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        super.setFullScopeAllowed(value);
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

        // Regenerate the proof for this client when scope is updated true or false.
        proofGeneration.regenerateProofForClient(client, usersInClient);
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
