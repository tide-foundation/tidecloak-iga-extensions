package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaRealmProvider;

import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;


public class TideRealmProvider extends JpaRealmProvider {
    private final KeycloakSession session;

    public TideRealmProvider(KeycloakSession session, EntityManager em, Set<String> clientSearchableAttributes, Set<String> groupSearchableAttributes) {
        super(session, em, clientSearchableAttributes, groupSearchableAttributes);
        this.session = session;
    }

    @Override
    public RealmModel createRealm(String name) {
        return createRealm(KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RealmModel createRealm(String id, String name) {
        RealmEntity realm = new RealmEntity();
        realm.setName(name);
        realm.setId(id);
        em.persist(realm);
        em.flush();
        final RealmModel adapter = new TideRealmAdapter(session, em, realm);
        session.getKeycloakSessionFactory().publish(new RealmModel.RealmCreationEvent() {
            @Override
            public RealmModel getCreatedRealm() {
                return adapter;
            }
            @Override
            public KeycloakSession getKeycloakSession() {
                return session;
            }
        });
        return adapter;
    }

    @Override
    public ClientModel addClient(RealmModel realm, String clientId) {
        return addClient(realm, KeycloakModelUtils.generateId(), clientId);
    }

    @Override
    public ClientModel addClient(RealmModel realm, String id, String clientId) {
        ClientModel clientModel = super.addClient(realm, id, clientId);
        createAndAddProtocolMapper(clientModel, "tideuserkey", "tideUserKey", "Tide User Key");
        createAndAddProtocolMapper(clientModel, "vuid", "vuid", "Tide vuid");
        createAndAddRolesMapper(clientModel, "", "Tide IGA Role Mapper");
        ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
        return new TideClientAdapter(realm, em, session, clientEntity);
    }

    @Override
    public boolean removeRole(RoleModel role) {
        // Deletion of roles need to be first approved
        // Check if draft record already exists
        RoleEntity roleEntity = TideRolesUtil.toRoleEntity(role, em);

        List<TideRoleDraftEntity> drafts = em.createNamedQuery("getRoleDraftByRoleEntityAndDeleteStatus", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .getResultList();

        if (drafts != null && !drafts.isEmpty()){
            TideRoleDraftEntity draft = drafts.get(0);
            em.remove(draft);
            em.flush();
            return super.removeRole(role);
        }

        else {
            // generate proof drafts for affected users for this change request
            if (role.getContainer() instanceof  ClientModel) {
                RealmModel realm = ((ClientModel)role.getContainer()).getRealm();
                List<UserModel> users =  session.users().getRoleMembersStream(realm, role).toList();

                // If no users has this role granted, allow for removal of role.
                if (users.isEmpty()) {
                    return super.removeRole(role);

                }
                TideRoleDraftEntity newDeletionRequest = new TideRoleDraftEntity();
                newDeletionRequest.setId(KeycloakModelUtils.generateId());
                newDeletionRequest.setRole(roleEntity);
                newDeletionRequest.setDeleteStatus(DraftStatus.DRAFT);
                em.persist(newDeletionRequest);

                List<ClientModel> clientList = getUniqueClientList(role, realm);
                TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
                clientList.forEach(client -> {
                    users.forEach(user -> {
                        UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                        Set<RoleModel> roleMappings = new HashSet<>();
                        roleMappings.add(role); // this is the new role we are removing

                        try {
                            util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, newDeletionRequest.getId(), ChangeSetType.ROLE, ActionType.DELETE, client.isFullScopeAllowed());
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    });
                });

            }

            em.flush();
            // Can we return a better message here ?
            // e.g. change request created
            return true;
        }

    }

    @Override
    public void moveGroup(RealmModel realm, GroupModel group, GroupModel toParent){
        super.moveGroup(realm, group, toParent);

        // get group inherited roles, we just need the client to regen
        GroupModel movedGroup = session.groups().getGroupById(realm, group.getId());

        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        // get effective roles
        List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(movedGroup);
        // Initialize proof generation

        // Recursively handle proof regeneration for all members in the hierarchy of the group
        List<UserModel> members = proofGeneration.getAllGroupMembersIncludingSubgroups(realm, movedGroup);
        proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, members);

    }
    @Override
    public RoleModel addClientRole(ClientModel client, String name) {
        return addClientRole(client, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addClientRole(ClientModel client, String id, String name) {
        if (getClientRole(client, name) != null) {
            throw new ModelDuplicateException();
        }
        RoleEntity roleEntity = new RoleEntity();
        roleEntity.setId(id);
        roleEntity.setName(name);
        roleEntity.setRealmId(client.getRealm().getId());
        roleEntity.setClientId(client.getId());
        roleEntity.setClientRole(true);
        em.persist(roleEntity);
        return new TideRoleAdapter(session, client.getRealm(), em, roleEntity);
    }


    @Override
    public RoleModel addRealmRole(RealmModel realm, String name) {
        RoleModel roleModel = super.addRealmRole(realm, KeycloakModelUtils.generateId(), name);
        RoleEntity role = em.find(RoleEntity.class, roleModel.getId());
        return new TideRoleAdapter(session, realm, em, role);

    }
    @Override
    public RoleModel addRealmRole(RealmModel realm, String id, String name) {
        RoleModel roleModel = super.addRealmRole(realm, id, name);
        RoleEntity role = em.find(RoleEntity.class, roleModel.getId());

        return new TideRoleAdapter(session, realm, em, role);

    }


    /**
     *
     * Same as super class, instead we explicity use the remove roles else it'll use the tide drafting delete
     *
     **/
    @Override
    public boolean removeRealm(String id) {
        RealmEntity realm = (RealmEntity)this.em.find(RealmEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
        if (realm == null) {
            return false;
        } else {
            final RealmAdapter adapter = new RealmAdapter(this.session, this.em, realm);
            this.session.users().preRemove(adapter);
            realm.getDefaultGroupIds().clear();
            this.em.flush();
            this.em.createNamedQuery("deleteGroupRoleMappingsByRealm").setParameter("realm", realm.getId()).executeUpdate();
            session.clients().removeClients(adapter);
            this.em.createNamedQuery("deleteDefaultClientScopeRealmMappingByRealm").setParameter("realm", realm).executeUpdate();
            this.session.clientScopes().removeClientScopes(adapter);
            adapter.getRolesStream().forEach(this::removeRoleOnRealmDelete);
            Stream<GroupModel> var10000 = this.session.groups().getTopLevelGroupsStream(adapter);
            Objects.requireNonNull(adapter);
            var10000.forEach(adapter::removeGroup);
            this.em.createNamedQuery("removeClientInitialAccessByRealm").setParameter("realm", realm).executeUpdate();
            this.em.remove(realm);
            this.em.flush();
            this.em.clear();
            this.session.getKeycloakSessionFactory().publish(new RealmModel.RealmRemovedEvent() {
                public RealmModel getRealm() {
                    return adapter;
                }

                public KeycloakSession getKeycloakSession() {
                    return TideRealmProvider.this.session;
                }
            });
            return true;
        }
    }

    public void removeRoleOnRealmDelete(RoleModel role) {
        RealmModel realm;
        if (role.getContainer() instanceof RealmModel) {
            realm = (RealmModel)role.getContainer();
        } else {
            if (!(role.getContainer() instanceof ClientModel)) {
                throw new IllegalStateException("RoleModel's container isn not instance of either RealmModel or ClientModel");
            }

            realm = ((ClientModel)role.getContainer()).getRealm();
        }
        this.session.users().preRemove(realm, role);
        RoleEntity roleEntity = (RoleEntity)this.em.getReference(RoleEntity.class, role.getId());
        if (roleEntity != null && roleEntity.getRealmId().equals(realm.getId())) {
            String compositeRoleTable = JpaUtils.getTableNameForNativeQuery("COMPOSITE_ROLE", this.em);
            this.em.createNativeQuery("delete from " + compositeRoleTable + " where CHILD_ROLE = :role").setParameter("role", roleEntity.getId()).executeUpdate();
            this.em.createNamedQuery("deleteClientScopeRoleMappingByRole").setParameter("role", roleEntity).executeUpdate();
            this.em.flush();
            this.em.remove(roleEntity);
            this.session.getKeycloakSessionFactory().publish(this.roleRemovedEvent(role));
            this.em.flush();
        } else {
            throw new ModelException("Role not found or trying to remove role from incorrect realm");
        }
    }

    @Override
    public boolean removeClient(RealmModel realm, String id) {
        logger.tracef("removeClient(%s, %s)%s", realm, id, getShortStackTrace());

        final ClientModel client = getClientById(realm, id);
        if (client == null) return false;

        session.users().preRemove(realm, client);
        client.getRolesStream().forEach(this::removeRoleOnRealmDelete);
        ClientEntity clientEntity = em.find(ClientEntity.class, id, LockModeType.PESSIMISTIC_WRITE);

        session.getKeycloakSessionFactory().publish(new ClientModel.ClientRemovedEvent() {
            @Override
            public ClientModel getClient() {
                return client;
            }

            @Override
            public KeycloakSession getKeycloakSession() {
                return session;
            }
        });

        int countRemoved = em.createNamedQuery("deleteClientScopeClientMappingByClient")
                .setParameter("clientId", clientEntity.getId())
                .executeUpdate();
        em.remove(clientEntity);  // i have no idea why, but this needs to come before deleteScopeMapping

        try {
            em.flush();
        } catch (RuntimeException e) {
            logger.errorv("Unable to delete client entity: {0} from realm {1}", client.getClientId(), realm.getName());
            throw e;
        }

        return true;
    }

    /**
     *
     * We are returning our TideGroupAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public GroupModel getGroupById(RealmModel realm, String id) {
        GroupModel group = super.getGroupById(realm, id);
        if ( group == null) {
            return null;
        }
        GroupEntity groupEntity = em.getReference(GroupEntity.class, group.getId());
        return new TideGroupAdapter(realm, em, groupEntity, session);
    }

    @Override
    public Stream<GroupModel> getGroupsByRoleStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        Stream<GroupModel> groups = super.getGroupsByRoleStream(realm, role, firstResult, maxResults)
                .map(group -> {
                    GroupEntity groupEntity = em.getReference(GroupEntity.class, group.getId());
                    return new TideGroupAdapter(realm, em, groupEntity, session);
                });

        return groups.sorted(GroupModel.COMPARE_BY_NAME);
    }

    @Override
    public GroupModel createGroup(RealmModel realm, String id, String name, GroupModel toParent) {
        GroupModel group = super.createGroup(realm, id, name, toParent);
        if ( group == null) {
            return null;
        }
        GroupEntity groupEntity = em.getReference(GroupEntity.class, group.getId());
        return new TideGroupAdapter(realm, em, groupEntity, session);
    }

    @Override
    public Stream<GroupModel> searchGroupsByAttributes(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        return super.searchGroupsByAttributes(realm, attributes, firstResult, maxResults)
                .map(group -> {
                    GroupEntity groupEntity = em.getReference(GroupEntity.class, group.getId());
                    return new TideGroupAdapter(realm, em, groupEntity, session);
                });
    }

    /**
     *
     * We are returning our TideClientAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public ClientModel getClientByClientId(RealmModel realm, String clientId) {
        ClientModel client = super.getClientByClientId(realm, clientId);
        if ( client == null) {
            return null;
        }
        ClientEntity clientEntity = em.getReference(ClientEntity.class, client.getId());
        return new TideClientAdapter(realm, em, session, clientEntity);
    }

    @Override
    public ClientModel getClientById(RealmModel realm, String id) {
        ClientModel client = super.getClientById(realm, id);
        if ( client == null) {
            return null;
        }
        ClientEntity clientEntity = em.getReference(ClientEntity.class, client.getId());
        return new TideClientAdapter(realm, em, session, clientEntity);
    }

    /**
     *
     * We are returning our TideRoleAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public RoleModel getRoleById(RealmModel realm, String id) {
        RoleModel role = super.getRoleById(realm, id);
        if ( role == null) {
            return null;
        }
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        return new TideRoleAdapter(session, realm, em, roleEntity);
    }

    @Override
    public Stream<RoleModel> searchForClientRolesStream(RealmModel realm, String search, Stream<String> excludedIds, Integer first, Integer max) {
        return super.searchForClientRolesStream(realm, search, excludedIds, first, max)
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                });
    }

    @Override
    public Stream<RoleModel> searchForRolesStream(RealmModel realm, String search, Integer first, Integer max) {
        return super.searchForRolesStream(realm, search, first, max)
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                });
    }

    @Override
    public Stream<RoleModel> getClientRolesStream(ClientModel client, Integer first, Integer max) {
        return super.getClientRolesStream(client, first, max)
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, client.getRealm(), em, roleEntity);
                });
    }

    /**
     *
     * We are returning our TideRealmAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public RealmModel getRealmByName(String name) {
        RealmModel realm = super.getRealmByName(name);
        if ( realm == null) {
            return null;
        }
        RealmEntity realmEntity = em.getReference(RealmEntity.class, realm.getId());
        return new TideRealmAdapter(session, em, realmEntity);
    }

    @Override
    public RealmModel getRealm(String id) {
        RealmModel realm = super.getRealm(id);
        if ( realm == null) {
            return null;
        }
        RealmEntity realmEntity = em.getReference(RealmEntity.class, realm.getId());
        return new TideRealmAdapter(session, em, realmEntity);
    }

    private List<ClientModel> getUniqueClientList(RoleModel role, RealmModel realm) {
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        clientList.add((ClientModel) role.getContainer());

        return clientList.stream().distinct().collect(Collectors.toList());
    }

    private static void createAndAddProtocolMapper(ClientModel clientModel,
                                                  String claimName,
                                                  String userAttribute,
                                                  String mapperName) {

        // Create a new ProtocolMapperRepresentation
        ProtocolMapperRepresentation rep = new ProtocolMapperRepresentation();

        // Set the mapper's name, protocol type, and protocol mapper type
        rep.setName(mapperName);
        rep.setProtocol("openid-connect");
        rep.setProtocolMapper("oidc-usermodel-attribute-mapper");

        // Set the configuration for the mapper dynamically
        rep.setConfig(Map.of(
                "claim.name", claimName,            // The dynamic claim name
                "jsonType.label", "String",         // JSON type label (can be other types like boolean, etc.)
                "id.token.claim", "true",           // Include in ID token
                "access.token.claim", "true",       // Include in Access token
                "userinfo.token.claim", "true",     // Include in UserInfo endpoint
                "introspection.token.claim", "true",// Include in Introspection
                "lightweight.claim", "true",        // Lightweight claim
                "user.attribute", userAttribute     // The dynamic user attribute to map
        ));

        // Convert the ProtocolMapperRepresentation to ProtocolMapperModel
        ProtocolMapperModel model = RepresentationToModel.toModel(rep);

        // Add the protocol mapper to the client
        clientModel.addProtocolMapper(model);
    }

    private static void createAndAddRolesMapper(ClientModel clientModel,
                                               String claimName,
                                               String mapperName) {
        // Create a new ProtocolMapperRepresentation
        ProtocolMapperRepresentation rep = new ProtocolMapperRepresentation();

        // Set the mapper's name, protocol type, and protocol mapper type
        rep.setName(mapperName);
        rep.setProtocol("openid-connect");
        rep.setProtocolMapper("tide-roles-mapper");

        // Set the configuration for the mapper dynamically
        rep.setConfig(Map.of(
                "claim.name", claimName,              // The dynamic claim name (can be empty)
                "access.token.claim", "true",         // Include in Access token
                "lightweight.claim", "true"           // Lightweight claim
        ));

        // Convert the ProtocolMapperRepresentation to ProtocolMapperModel
        ProtocolMapperModel model = RepresentationToModel.toModel(rep);

        // Add the protocol mapper to the client
        clientModel.addProtocolMapper(model);
    }
}
