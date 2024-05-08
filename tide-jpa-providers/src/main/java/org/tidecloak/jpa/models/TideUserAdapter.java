package org.tidecloak.jpa.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.keycloak.Config;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.Protocol.mapper.TideRolesUtil;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;
import static org.tidecloak.AdminRealmResource.TideAdminRealmResource.*;

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

//        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//        List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(group);
//        UserModel user = session.users().getUserById(realm, getEntity().getId());
//        proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, List.of(user));
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
    public void grantRole(RoleModel role) {
        super.grantRole(role);

        // Check if this has already been action before
        Stream<TideUserRoleMappingDraftEntity> entity =  em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusAndAction", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("actionType", ActionType.CREATE)
                .getResultStream();

        // Add draft request
        if (entity.toList().isEmpty()) {
            var draftUserRole = new TideUserRoleMappingDraftEntity();
            draftUserRole.setId(KeycloakModelUtils.generateId());
            draftUserRole.setRoleId(role.getId());
            draftUserRole.setUser(this.getEntity());
            draftUserRole.setAction(ActionType.CREATE);
            draftUserRole.setDraftStatus(DraftStatus.DRAFT);

            //TODO: CLEAN THIS UP, PUT IN PROOFGENERATION UTIL!!!
            ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
            if (role.getContainer() instanceof ClientModel) {
                List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
                UserModel user = session.users().getUserById(realm, getEntity().getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm, em);
                clientList.forEach(client -> {
                    session.getContext().setClient(client);
                    // generate proof, this should have all current access
                    AccessToken proof = proofGeneration.generateAccessToken(client, wrappedUser, "openid");
                    // Get request changes
                    Set<RoleModel> rolemappings = new HashSet<>();
                    rolemappings.add(role);
                    Set<RoleModel> activeRoles = getDeepUserRoleMappings(rolemappings, wrappedUser, session, realm, em);
                    Set<RoleModel> requestedAccess = getAccess(activeRoles, client, client.getClientScopes(false).values().stream());
                    setTokenClaims(proof, requestedAccess);

                    try {
                        ObjectMapper objectMapper = new ObjectMapper();
                        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

                        TideUserRoleMappingDraftEntity temp = new TideUserRoleMappingDraftEntity();
                        temp.setId(draftUserRole.getId());
                        temp.setUser(draftUserRole.getUser());
                        temp.setRoleId(draftUserRole.getRoleId());
                        temp.setAction(draftUserRole.getAction());
                        temp.setDraftStatus(draftUserRole.getDraftStatus());

                        JsonNode tempNode = objectMapper.valueToTree(temp);
                        var sortedTemp = ProofGeneration.sortJsonNode(tempNode);
                        String draftRecord = objectMapper.writeValueAsString(sortedTemp);
                        String proofDraft = proofGeneration.cleanProofDraft(proof);
                        System.out.println(draftRecord); // <-- this is the draft record
                        System.out.println(proofDraft.concat(draftRecord)); // <-- this is the draft record

                        // store proof detail into db

                        AccessProofDetailEntity accessProofEntity = new AccessProofDetailEntity();
                        accessProofEntity.setId(KeycloakModelUtils.generateId());
                        accessProofEntity.setClientId(client.getId());
                        accessProofEntity.setUser(draftUserRole.getUser());
                        accessProofEntity.setRecordId(draftUserRole.getId());
                        accessProofEntity.setProofDraft(proofDraft);
                        accessProofEntity.setChangesetType(ChangeSetType.USER_ROLE);

                        em.persist(accessProofEntity);

                    } catch (JsonProcessingException e) {
                        throw new RuntimeException("Failed to process token", e);
                    }

                    em.persist(draftUserRole);
                    em.flush();

                });
            }
        }

    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
//        Optional<ClientModel> clientModel = Optional.empty();
//        if (role.getContainer() instanceof ClientModel){
//            clientModel = Optional.of((ClientModel) role.getContainer());
//        }
//        super.deleteRoleMapping(role);
//
//        if(clientModel.isPresent()){
//            List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
//            clientList.add(clientModel.get());
//            ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//            clientList.forEach(client -> {
//                proofGeneration.generateProofAndSaveToTable(user.getId(), client);
//            });
//        }

        // Check if role mapping is a draft
        Stream<TideUserRoleMappingDraftEntity> entity =  em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .getResultStream();

        if(!entity.toList().isEmpty()){
            em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                    .setParameter("roleId", role.getId())
                    .executeUpdate();
            super.deleteRoleMapping(role);
        } else {
            // GET APPROVAL FOR DELETION
            TideUserRoleMappingDraftEntity newEntity = new TideUserRoleMappingDraftEntity();
            newEntity.setId(KeycloakModelUtils.generateId());
            newEntity.setUser(getEntity());
            newEntity.setRoleId(role.getId());
            newEntity.setDraftStatus(DraftStatus.DRAFT);
            newEntity.setAction(ActionType.DELETE);
            em.persist(newEntity);
            em.flush();
            em.detach(newEntity);
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


    public Stream<RoleModel> getRoleMappingsStreamByStatus(DraftStatus status) {
        TypedQuery<String> query = em.createNamedQuery("filterUserRoleMappings", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }
    public Stream<RoleModel> getRoleMappingsStreamByAction(ActionType actionType) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityByAction", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("actionType", actionType);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }
    public Stream<RoleModel> getRoleMappingsStreamByStatusAndAction(DraftStatus status, ActionType actionType) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityIdsByStatusAndAction", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        query.setParameter("actionType", actionType);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

    private TypedQuery<String> createGetGroupsQuery() {
        // we query ids only as the group  might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<String> queryBuilder = builder.createQuery(String.class);
        Root<UserGroupMembershipEntity> root = queryBuilder.from(UserGroupMembershipEntity.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(builder.equal(root.get("user"), getEntity()));

        queryBuilder.select(root.get("groupId"));
        queryBuilder.where(predicates.toArray(new Predicate[0]));

        return em.createQuery(queryBuilder);
    }
}
