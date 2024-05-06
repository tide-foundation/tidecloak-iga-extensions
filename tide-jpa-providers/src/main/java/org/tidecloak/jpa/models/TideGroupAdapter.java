package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.models.*;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.GroupRoleMappingEntity;
import org.keycloak.models.utils.RoleUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideGroupRoleMappingEntity;
import org.tidecloak.jpa.utils.ProofGeneration;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;

public class TideGroupAdapter extends GroupAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;

    public TideGroupAdapter(RealmModel realm, EntityManager em, GroupEntity group, KeycloakSession session) {
        super(realm, em, group);
        this.session = session;
        this.realm = realm;
    }

    @Override
    public void grantRole(RoleModel role) {
        super.grantRole(role);
        TideGroupRoleMappingEntity entity = new TideGroupRoleMappingEntity();
        entity.setGroup(getEntity());
        entity.setRoleId(role.getId());
        entity.setDraftStatus(DraftStatus.DRAFT);
        entity.setAction(ActionType.CREATE);
        em.persist(entity);
        em.flush();
        em.detach(entity);


//        if (role.getContainer() instanceof ClientModel clientModel) {
//            GroupEntity groupEntity = getEntity();
//            GroupModel group = session.groups().getGroupById(realm, groupEntity.getId());
//            ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//            List<UserModel> users = proofGeneration.getAllGroupMembersIncludingSubgroups(realm, group);
//            // Regen for any clients with full scope enabled as well
//            List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
//            clientList.add(clientModel);
//
//            users.forEach(user -> {
//                clientList.forEach(client ->{
//                    proofGeneration.generateProofAndSaveToTable(user.getId(), client);
//                });
//            });
//        }
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        Optional<ClientModel> clientModel = Optional.empty();
        List<UserModel> users = new ArrayList<>();
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);

        // First, gather all necessary details before deletion
        if (role.getContainer() instanceof ClientModel) {
            clientModel = Optional.of((ClientModel) role.getContainer());
            GroupEntity groupEntity = getEntity();  // Retrieve only if needed
            GroupModel group = session.groups().getGroupById(realm, groupEntity.getId());
            users = proofGeneration.getAllGroupMembersIncludingSubgroups(realm, group);
        }
        // Perform the deletion
        super.deleteRoleMapping(role);
        // Regenerate tokens if necessary
        List<UserModel> finalUsers = users;

        clientModel.ifPresent(c -> {
            // Regen for any clients with full scope enabled as well
            List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
            clientList.add(c);
            finalUsers.forEach(user -> {
                clientList.forEach(client -> {
                    try {
                        proofGeneration.generateProofAndSaveToTable(user.getId(), client);
                    } catch (Exception e) {
                        System.err.println("Failed to regenerate token for user: " + user.getId());
                    }
                });

            });
        });
    }

    public Stream<RoleModel> getRealmRoleMappingsStreamByStatus(DraftStatus draftStatus) {
        return getRoleMappingsStreamByStatus(draftStatus).filter(RoleUtils::isRealmRole);
    }


    public Stream<RoleModel> getRoleMappingsStreamByStatus(DraftStatus draftStatus) {
        // we query ids only as the role might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        TypedQuery<String> query = em.createNamedQuery("groupRoleMappingDraftIdsByStatus", String.class);
        query.setParameter("group", getEntity());
        query.setParameter("draftStatus", draftStatus);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

}
