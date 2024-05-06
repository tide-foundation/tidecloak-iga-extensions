package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.*;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.client.clienttype.ClientTypeManager;
import org.keycloak.common.Profile;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaRealmProvider;

import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.jpa.utils.ProofGeneration;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;
import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;
import static org.keycloak.utils.StreamsUtil.closing;


public class TideRealmProvider extends JpaRealmProvider {
    private final KeycloakSession session;
    private final Set<String> groupSearchableAttributes;

    public TideRealmProvider(KeycloakSession session, EntityManager em, Set<String> clientSearchableAttributes, Set<String> groupSearchableAttributes) {
        super(session, em, clientSearchableAttributes, groupSearchableAttributes);
        this.session = session;
        this.groupSearchableAttributes = groupSearchableAttributes;
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
        ClientModel resource;

        if (id == null) {
            id = KeycloakModelUtils.generateId();
        }

        if (clientId == null) {
            clientId = id;
        }

        logger.tracef("addClient(%s, %s, %s)%s", realm, id, clientId, getShortStackTrace());

        ClientEntity entity = new ClientEntity();
        entity.setId(id);
        entity.setClientId(clientId);
        entity.setEnabled(true);
        entity.setStandardFlowEnabled(true);
        entity.setRealmId(realm.getId());
        em.persist(entity);

        resource = toClientModel(realm, entity);

//        Stream<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>());
//        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//        usersInRealm.forEach(user -> {
//            proofGeneration.generateProofAndSaveToTable(user.getId(), resource);
//        });

        session.getKeycloakSessionFactory().publish((ClientModel.ClientCreationEvent) () -> resource);
        return resource;
    }

    @Override
    public boolean removeRole(RoleModel role) {
        Optional<ClientModel> optionalClient = Optional.empty();
        List<UserModel> users = new ArrayList<>();

        // Check if role is associated with a ClientModel and collect relevant users
        if (role.getContainer() instanceof ClientModel client) {
            optionalClient = Optional.of(client);
            // Fetching users with a specific role in a given realm.
            RealmModel realm = client.getRealm();
            users = session.users().searchForUserStream(realm, new HashMap<>())
                    .filter(user -> user.hasRole(role))
                    .collect(Collectors.toList());
        }

        // Attempt to remove the role
        boolean isRoleDeleted = super.removeRole(role);

        // Regenerate tokens if the role was successfully removed
        if (isRoleDeleted) {
            List<UserModel> finalUsers = users;
            optionalClient.ifPresent(client -> {
                ProofGeneration proofGeneration = new ProofGeneration(session, client.getRealm(), em);
                for (UserModel user : finalUsers) {
                    try {
                        proofGeneration.generateProofAndSaveToTable(user.getId(), client);

                    } catch (Exception e) {
                        System.err.println("Failed to regenerate token for user: " + user.getId() + e);
                    }
                }
            });
        }
        return isRoleDeleted;
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
        TideRoleAdapter adapter = new TideRoleAdapter(session, client.getRealm(), em, roleEntity);
        return adapter;
    }


    @Override
    public RoleModel addRealmRole(RealmModel realm, String name) {
        return addRealmRole(realm, KeycloakModelUtils.generateId(), name);

    }
    @Override
    public RoleModel addRealmRole(RealmModel realm, String id, String name) {
        if (getRealmRole(realm, name) != null) {
            throw new ModelDuplicateException();
        }
        RoleEntity entity = new RoleEntity();
        entity.setId(id);
        entity.setName(name);
        entity.setRealmId(realm.getId());
        em.persist(entity);
        em.flush();
        TideRoleAdapter adapter = new TideRoleAdapter(session, realm, em, entity);
        return adapter;

    }




    /**
     *
     * We are returning our TideGroupAdapter here. Everything else works the same as the super
     *
     **/


    @Override
    public GroupModel getGroupById(RealmModel realm, String id) {
        GroupEntity groupEntity = em.find(GroupEntity.class, id);
        if (groupEntity == null) return null;
        if (!groupEntity.getRealm().equals(realm.getId())) return null;
        TideGroupAdapter adapter =  new TideGroupAdapter(realm, em, groupEntity, session);
        return adapter;
    }


    @Override
    public Stream<GroupModel> getGroupsByRoleStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        TypedQuery<GroupEntity> query = em.createNamedQuery("groupsInRole", GroupEntity.class);
        query.setParameter("roleId", role.getId());

        Stream<GroupEntity> results = paginateQuery(query, firstResult, maxResults).getResultStream();

        return closing(results
                .map(g -> (GroupModel) new TideGroupAdapter(realm, em, g, session))
                .sorted(GroupModel.COMPARE_BY_NAME));
    }

    @Override
    public GroupModel createGroup(RealmModel realm, String id, String name, GroupModel toParent) {
        if (id == null) {
            id = KeycloakModelUtils.generateId();
        } else if (GroupEntity.TOP_PARENT_ID.equals(id)) {
            // maybe it's impossible but better ensure this doesn't happen
            throw new ModelException("The ID of the new group is equals to the tag used for top level groups");
        }
        GroupEntity groupEntity = new GroupEntity();
        groupEntity.setId(id);
        groupEntity.setName(name);
        groupEntity.setRealm(realm.getId());
        groupEntity.setParentId(toParent == null ? GroupEntity.TOP_PARENT_ID : toParent.getId());
        em.persist(groupEntity);
        em.flush();

        return new TideGroupAdapter(realm, em, groupEntity, session);

    }

    @Override
    public Stream<GroupModel> searchGroupsByAttributes(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        Map<String, String> filteredAttributes = groupSearchableAttributes == null || groupSearchableAttributes.isEmpty()
                ? attributes
                : attributes.entrySet().stream().filter(m -> groupSearchableAttributes.contains(m.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<GroupEntity> queryBuilder = builder.createQuery(GroupEntity.class);
        Root<GroupEntity> root = queryBuilder.from(GroupEntity.class);

        List<Predicate> predicates = new ArrayList<>();

        predicates.add(builder.equal(root.get("realm"), realm.getId()));

        for (Map.Entry<String, String> entry : filteredAttributes.entrySet()) {
            String key = entry.getKey();
            if (key == null || key.isEmpty()) {
                continue;
            }
            String value = entry.getValue();

            Join<GroupEntity, GroupAttributeEntity> attributeJoin = root.join("attributes");

            Predicate attrNamePredicate = builder.equal(attributeJoin.get("name"), key);
            Predicate attrValuePredicate = builder.equal(attributeJoin.get("value"), value);
            predicates.add(builder.and(attrNamePredicate, attrValuePredicate));
        }

        Predicate finalPredicate = builder.and(predicates.toArray(new Predicate[0]));
        queryBuilder.where(finalPredicate).orderBy(builder.asc(root.get("name")));

        TypedQuery<GroupEntity> query = em.createQuery(queryBuilder);
        return closing(paginateQuery(query, firstResult, maxResults).getResultStream())
                .map(g -> new TideGroupAdapter(realm, em, g, session));
    }

    /**
     *
     * We are returning our TideClientAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public ClientModel getClientByClientId(RealmModel realm, String clientId) {
        logger.tracef("getClientByClientId(%s, %s)%s", realm, clientId, getShortStackTrace());

        TypedQuery<String> query = em.createNamedQuery("findClientIdByClientId", String.class);
        query.setParameter("clientId", clientId);
        query.setParameter("realm", realm.getId());
        List<String> results = query.getResultList();
        if (results.isEmpty()) return null;
        String id = results.get(0);
        return session.clients().getClientById(realm, id);
    }
    @Override
    public ClientModel getClientById(RealmModel realm, String id) {
        logger.tracef("getClientById(%s, %s)%s", realm, id, getShortStackTrace());

        ClientEntity client = em.find(ClientEntity.class, id);
        // Check if client belongs to this realm
        if (client == null || !realm.getId().equals(client.getRealmId())) return null;
        return toClientModel(realm, client);
    }

    private ClientModel toClientModel(RealmModel realm, ClientEntity client) {
        TideClientAdapter adapter = new TideClientAdapter(realm, em, session, client);

        if (Profile.isFeatureEnabled(Profile.Feature.CLIENT_TYPES)) {
            ClientTypeManager mgr = session.getProvider(ClientTypeManager.class);
            return mgr.augmentClient(adapter);
        } else {
            return adapter;
        }
    }

    /**
     *
     * We are returning our TideRoleAdapter here. Everything else works the same as the super
     *
     **/

    @Override
    public RoleModel getRoleById(RealmModel realm, String id) {
        RoleEntity entity = em.find(RoleEntity.class, id);
        if (entity == null) return null;
        if (!realm.getId().equals(entity.getRealmId())) return null;
        TideRoleAdapter adapter = new TideRoleAdapter(session, realm, em, entity);
        return adapter;
    }

    @Override
    public Stream<RoleModel> searchForClientRolesStream(RealmModel realm, String search, Stream<String> excludedIds, Integer first, Integer max) {
        return searchForClientRolesStream(realm, excludedIds, search, first, max, true);
    }

    private Stream<RoleModel> searchForClientRolesStream(RealmModel realm, Stream<String> ids, String search, Integer first, Integer max, boolean negateIds) {
        List<String> idList = null;
        if(ids != null) {
            idList = ids.collect(Collectors.toList());
            if(idList.isEmpty() && !negateIds)
                return Stream.empty();
        }
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<RoleEntity> query = cb.createQuery(RoleEntity.class);

        Root<RoleEntity> roleRoot = query.from(RoleEntity.class);
        Root<ClientEntity> clientRoot = query.from(ClientEntity.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.equal(roleRoot.get("realmId"), realm.getId()));
        predicates.add(cb.isTrue(roleRoot.get("clientRole")));
        predicates.add(cb.equal(roleRoot.get("clientId"),clientRoot.get("id")));
        if(search != null && !search.isEmpty()) {
            search = "%" + search.trim().toLowerCase() + "%";
            predicates.add(cb.or(
                    cb.like(cb.lower(roleRoot.get("name")), search),
                    cb.like(cb.lower(clientRoot.get("clientId")), search)
            ));
        }
        if(idList != null && !idList.isEmpty()) {
            Predicate idFilter = roleRoot.get("id").in(idList);
            if(negateIds) idFilter = cb.not(idFilter);
            predicates.add(idFilter);
        }
        query.select(roleRoot).where(predicates.toArray(new Predicate[0]))
                .orderBy(
                        cb.asc(clientRoot.get("clientId")),
                        cb.asc(roleRoot.get("name")));
        return closing(paginateQuery(em.createQuery(query),first,max).getResultStream())
                .map(roleEntity -> new TideRoleAdapter(session, realm, em, roleEntity));
    }

    @Override
    public Stream<RoleModel> searchForRolesStream(RealmModel realm, String search, Integer first, Integer max) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("searchForRealmRoles", RoleEntity.class);
        query.setParameter("realm", realm.getId());

        return searchForRoles(query, realm, search, first, max);
    }

    protected Stream<RoleModel> searchForRoles(TypedQuery<RoleEntity> query, RealmModel realm, String search, Integer first, Integer max) {
        query.setParameter("search", "%" + search.trim().toLowerCase() + "%");
        Stream<RoleEntity> results = paginateQuery(query, first, max).getResultStream();

        return closing(results.map(role -> new TideRoleAdapter(session, realm, em, role)));
    }

    @Override
    public Stream<RoleModel> getClientRolesStream(ClientModel client, Integer first, Integer max) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("getClientRoles", RoleEntity.class);
        query.setParameter("client", client.getId());

        return getRolesStream(query, client.getRealm(), first, max);
    }

    protected Stream<RoleModel> getRolesStream(TypedQuery<RoleEntity> query, RealmModel realm, Integer first, Integer max) {
        Stream<RoleEntity> results = paginateQuery(query, first, max).getResultStream();

        return closing(results.map(role -> new TideRoleAdapter(session, realm, em, role)));
    }



    @Override
    public RealmModel getRealmByName(String name) {
        TypedQuery<String> query = em.createNamedQuery("getRealmIdByName", String.class);
        query.setParameter("name", name);
        List<String> entities = query.getResultList();
        if (entities.isEmpty()) return null;
        if (entities.size() > 1) throw new IllegalStateException("Should not be more than one realm with same name");
        String id = query.getResultList().get(0);

        return getRealm(id);
    }
    @Override
    public RealmModel getRealm(String id) {
        RealmEntity realm = em.find(RealmEntity.class, id);
        if (realm == null) return null;
        TideRealmAdapter adapter = new TideRealmAdapter(session, em, realm);
        return adapter;
    }

}
