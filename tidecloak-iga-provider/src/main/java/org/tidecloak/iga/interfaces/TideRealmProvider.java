package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.Config;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaRealmProvider;

import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.services.Urls;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;


public class TideRealmProvider extends JpaRealmProvider {
    private final KeycloakSession session;
    private final ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();;


    public TideRealmProvider(KeycloakSession session, EntityManager em, Set<String> clientSearchableAttributes, Set<String> groupSearchableAttributes) {
        super(session, em, clientSearchableAttributes, groupSearchableAttributes);
        this.session = session;
    }

    @Override
    public ClientModel addClient(RealmModel realm, String clientId) {
        try {
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            // Dont draft for master realm or IGA disabled realms
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            ClientModel client = addClient(realm, KeycloakModelUtils.generateId(), clientId);
            if(!isIGAEnabled || realm.equals(masterRealm)) {
                return client;
            }
            ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());
            List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();

            TideClientDraftEntity clientDraftEntity = new TideClientDraftEntity();
            clientDraftEntity.setId(KeycloakModelUtils.generateId());
            clientDraftEntity.setClient(clientEntity);

            if(usersInRealm.isEmpty()) {
                clientDraftEntity.setFullScopeEnabled(DraftStatus.ACTIVE);
                clientDraftEntity.setFullScopeDisabled(DraftStatus.NULL);
                clientEntity.setFullScopeAllowed(true);
            } else {
                clientDraftEntity.setFullScopeDisabled(DraftStatus.ACTIVE);
                clientDraftEntity.setFullScopeEnabled(DraftStatus.NULL);
                clientEntity.setFullScopeAllowed(false);
            }
            clientDraftEntity.setAction(ActionType.CREATE);
            em.persist(clientDraftEntity);
            em.flush();

            if(client.getRealm().getName().equalsIgnoreCase(Config.getAdminRealm())) {
                return client;
            }
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
            changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT).executeWorkflow(session, clientDraftEntity, em, WorkflowType.REQUEST, params, null);
            return client;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ClientModel addClient(RealmModel realm, String id, String clientId) {
        ClientModel clientModel = super.addClient(realm, id, clientId);
        createAndAddProtocolMapper(clientModel, "tideuserkey", "tideUserKey", "Tide User Key");
        createAndAddProtocolMapper(clientModel, "vuid", "vuid", "Tide vuid");
        ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
        return new TideClientAdapter(realm, em, session, clientEntity);
    }

    @Override
    public boolean removeRole(RoleModel role) {
        try {
            // Deletion of roles need to be first approved
            // Check if draft record already exists
            RoleEntity roleEntity = TideEntityUtils.toRoleEntity(role, em);

            String igaAttribute = session.getContext().getRealm().getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            // Dont draft for master realm or for IGA disabled realms
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (!isIGAEnabled || session.getContext().getRealm().equals(masterRealm)){
                List<TideRoleDraftEntity> pendingDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                        .setParameter("role", roleEntity)
                        .getResultList();

                pendingDrafts.forEach(r -> em.remove(r));
                em.flush();
                return super.removeRole(role);
            }

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
            TideRoleDraftEntity newDeletionRequest = new TideRoleDraftEntity();
            newDeletionRequest.setId(KeycloakModelUtils.generateId());
            newDeletionRequest.setRole(roleEntity);
            newDeletionRequest.setDeleteStatus(DraftStatus.DRAFT);
            em.persist(newDeletionRequest);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.ROLE);
            changeSetProcessorFactory.getProcessor(ChangeSetType.ROLE).executeWorkflow(session, newDeletionRequest, em, WorkflowType.REQUEST, params, null);
            em.flush();
            // Can we return a better message here ?
            // e.g. change request created
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    @Override
    public void moveGroup(RealmModel realm, GroupModel group, GroupModel toParent){
        super.moveGroup(realm, group, toParent);

//        // get group inherited roles, we just need the client to regen
//        GroupModel movedGroup = session.groups().getGroupById(realm, group.getId());
//
//        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//        // get effective roles
//        List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(movedGroup);
//        // Initialize proof generation
//
//        // Recursively handle proof regeneration for all members in the hierarchy of the group
//        List<UserModel> members = proofGeneration.getAllGroupMembersIncludingSubgroups(realm, movedGroup);
//        proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, members);

    }
    @Override
    public RoleModel addClientRole(ClientModel client, String name) {
        return addClientRole(client, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addClientRole(ClientModel client, String id, String name) {
        RoleModel role = super.addClientRole(client, id, name);

        // Dont draft for master realm
        RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
        if(client.getRealm().equals(masterRealm)){
            return role;
        }

        List<TideRoleDraftEntity> roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", TideEntityUtils.toRoleEntity(role, em))
                .getResultList();

        if (!roleDraft.isEmpty()) {
            return new TideRoleAdapter(session, client.getRealm(), em, TideEntityUtils.toRoleEntity(role, em));
        }

        // Create Draft
        TideRoleDraftEntity clientRoleDraft = new TideRoleDraftEntity();
        clientRoleDraft.setId(KeycloakModelUtils.generateId());
        clientRoleDraft.setRole(TideEntityUtils.toRoleEntity(role, em));
        clientRoleDraft.setDraftStatus(DraftStatus.ACTIVE);
        em.persist(clientRoleDraft);

        return new TideRoleAdapter(session, client.getRealm(), em, TideEntityUtils.toRoleEntity(role, em));
    }

    @Override
    public RoleModel addRealmRole(RealmModel realmModel, String name) {
        return addRealmRole(realmModel, KeycloakModelUtils.generateId(), name);
    }
    @Override
    public RoleModel addRealmRole(RealmModel realm, String id, String name) {
        RoleModel role = super.addRealmRole(realm, id, name);

        // Dont draft for master realm
        RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
        if(realm.equals(masterRealm)){
            return role;
        }

        List<TideRoleDraftEntity> roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", TideEntityUtils.toRoleEntity(role, em))
                .getResultList();

        if (!roleDraft.isEmpty()) {
            return new TideRoleAdapter(session, realm, em, TideEntityUtils.toRoleEntity(role, em));
        }

        // Create Draft
        TideRoleDraftEntity realmRoleDraft = new TideRoleDraftEntity();
        realmRoleDraft.setId(KeycloakModelUtils.generateId());
        realmRoleDraft.setRole(TideEntityUtils.toRoleEntity(role, em));
        realmRoleDraft.setDraftStatus(DraftStatus.ACTIVE);
        em.persist(realmRoleDraft);

        return new TideRoleAdapter(session, realm, em, TideEntityUtils.toRoleEntity(role, em));

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
            List<TideClientDraftEntity> clientDraftEntities = em.createNamedQuery("getClientDraftDetails", TideClientDraftEntity.class).setParameter("client", clientEntity).getResultList();
            clientDraftEntities.forEach(e -> {
                List<ChangesetRequestEntity> changeRequestEntity = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class).setParameter("changesetRequestId", e.getId()).getResultList();
                if(!changeRequestEntity.isEmpty()){
                    changeRequestEntity.forEach(c -> em.remove(c));
                }

            });
            em.createNamedQuery("deleteClient").setParameter("client", clientEntity).executeUpdate();
            em.createNamedQuery("DeleteAllAccessProofsByClient").setParameter("clientId", clientEntity.getId()).executeUpdate();
            em.createNamedQuery("DeleteAllUserProofsByClient").setParameter("clientId", clientEntity.getId()).executeUpdate();
            em.flush();


        } catch (RuntimeException e) {
            logger.errorv("Unable to delete client entity: {0} from realm {1}", client.getClientId(), realm.getName());
            throw e;
        }

        return true;
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
