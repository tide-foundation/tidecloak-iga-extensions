package org.tidecloak.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.iga.interfaces.TideUserAdapter;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.tidecloak.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.ChangeSetProcessors.utils.ClientUtils.getUniqueClientList;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.removeRoleFromAccessToken;

public class RoleProcessor implements ChangeSetProcessor<TideRoleDraftEntity> {

    protected static final Logger logger = Logger.getLogger(RoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType actionType){
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.ROLE)
                .getResultList();
        pendingChanges.forEach(em::remove);

        List<TideRoleDraftEntity> pendingDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", entity.getRole())
                .getResultList();

        pendingDrafts.forEach(d -> {
            d.setDeleteStatus(DraftStatus.NULL);
        });
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.ROLE));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideRoleDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId(),
                entity.getChangeRequestId()
        ));

        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                commitRoleChangeRequest(realm, entity, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                entity.getId(),
                entity.getChangeRequestId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId(),
                    entity.getChangeRequestId()
            ));
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleDeleteRequest(session, entity, em, callback);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", action, entity.getId(), entity.getChangeRequestId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process ROLE request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        throw new Exception("ROLE creation not yet implementated");
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());
        List<UserModel> users = session.users().searchForUserStream(realm, new HashMap<>()).filter(u -> u.hasRole(role)).toList();
        if(users.isEmpty()){
            return;
        }
        entity.setAction(ActionType.DELETE);

        List<ClientModel> clientList = getUniqueClientList(session, realm, role);
        clientList.forEach(client -> {
            users.forEach(user -> {
                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                try {
                    ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, entity.getChangeRequestId(), ChangeSetType.ROLE, entity);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideRoleDraftEntity affectedRoleEntity = em.find(TideRoleDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedRoleEntity == null || (affectedRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && (affectedRoleEntity.getDeleteStatus() == null || affectedRoleEntity.getDeleteStatus().equals(DraftStatus.NULL))))
        {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedRoleEntity);
        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session,  RealmModel realm,TideRoleDraftEntity entity) {
        return realm.getRoleById(entity.getRole().getId());
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideRoleDraftEntity entity, UserModel user, ClientModel clientModel){
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());

        Set<RoleModel> tideRoleModel = Set.of(TideEntityUtils.toTideRoleAdapter(role, session, realm));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> roleModelSet = userContextUtils.expandActiveCompositeRoles(session, tideRoleModel);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        roleModelSet.forEach(r -> {
            if(change.getActionType().equals(ActionType.CREATE)){
                addRoleToAccessToken(token, r);
            } else if (change.getActionType().equals(ActionType.DELETE)) {
                removeRoleFromAccessToken(token, r);
            }
        });
        userContextUtils.normalizeAccessToken(token, clientModel.isFullScopeAllowed());
        return token;
    }

    @Override
    public void combineChangeRequests(KeycloakSession session, List<TideRoleDraftEntity> roleEntities, EntityManager em) {
        RealmModel realm = session.getContext().getRealm();
        ObjectMapper objectMapper = new ObjectMapper();

        // Group the change requests
        Map<UserClientKey, List<AccessProofDetailEntity>> groupedChangeRequests =
                ChangeSetProcessor.super.groupChangeRequests(roleEntities, em);

        // Prepare lists to defer persistence/removal
        List<TideRoleDraftEntity> modifiedEntities = new ArrayList<>();
        List<AccessProofDetailEntity> newCombinedProofs = new ArrayList<>();
        List<AccessProofDetailEntity> toRemoveProofs = new ArrayList<>();
        List<ChangesetRequestEntity> toRemoveChangeRequests = new ArrayList<>();
        String changeRequestId = KeycloakModelUtils.generateId();

        groupedChangeRequests.forEach((userClientAccess, accessProofs) -> {
            UserEntity userEntity = em.find(UserEntity.class, userClientAccess.getUserId());
            UserModel user = session.users().getUserById(realm, userClientAccess.getUserId());
            ClientModel client = realm.getClientById(userClientAccess.getClientId());
            AtomicReference<String> trackTokenString = new AtomicReference<>();

            accessProofs.forEach(proof -> {
                try {
                    // Initialize the first token only once
                    if (trackTokenString.get() == null || trackTokenString.get().isBlank()) {
                        trackTokenString.set(proof.getProofDraft());
                    }

                    // Fetch and detach the draft record entity
                    TideRoleDraftEntity entity =
                            (TideRoleDraftEntity) IGAUtils.fetchDraftRecordEntityByRequestId(
                                    em, proof.getChangesetType(), proof.getRecordId());

                    if (entity == null) {
                        throw new RuntimeException("Could not find entity with change request id " + proof.getRecordId());
                    }

                    em.detach(entity); // Prevent auto-flushing
                    entity.setChangeRequestId(changeRequestId);
                    modifiedEntities.add(entity);

                    // Parse token and re-combine into new context
                    AccessToken accessToken = objectMapper.readValue(trackTokenString.get(), AccessToken.class);
                    String combinedToken = this.combinedTransformedUserContext(
                            session, realm, client, user, "openId", entity, accessToken);
                    trackTokenString.set(combinedToken);

                    // Queue for removal
                    List<ChangesetRequestEntity> crEntities = em
                            .createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getRecordId())
                            .getResultList();

                    toRemoveChangeRequests.addAll(crEntities);
                    toRemoveProofs.add(proof);

                } catch (Exception e) {
                    throw new RuntimeException("Failed processing access proof: " + proof.getRecordId(), e);
                }
            });

            // After processing all proofs for this group, create the combined proof entity
            AccessProofDetailEntity combinedProof = new AccessProofDetailEntity();
            combinedProof.setUser(userEntity);
            combinedProof.setProofDraft(trackTokenString.get());
            combinedProof.setId(KeycloakModelUtils.generateId());
            combinedProof.setClientId(client.getId());
            combinedProof.setChangesetType(ChangeSetType.USER_ROLE);
            combinedProof.setRealmId(realm.getId());
            combinedProof.setRecordId(changeRequestId);
            newCombinedProofs.add(combinedProof);
        });

        // Persist all collected changes at once
        for (TideRoleDraftEntity entity : modifiedEntities) {
            em.merge(entity);
        }

        for (AccessProofDetailEntity combinedProof : newCombinedProofs) {
            em.persist(combinedProof);
        }

        toRemoveProofs.forEach(em::remove);
        toRemoveChangeRequests.forEach(em::remove);

        em.flush();
    }


    private void commitRoleChangeRequest(RealmModel realm, TideRoleDraftEntity entity, ChangeSetRequest change, EntityManager em) {;
        RoleModel role = realm.getRoleById(entity.getRole().getId());
        if (role == null) return;

        if (change.getActionType() == ActionType.CREATE) {
            if(entity.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);

        } else if (change.getActionType() == ActionType.DELETE) {
            if(entity.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            entity.setDeleteStatus(DraftStatus.ACTIVE);
            realm.removeRole(role);
            cleanupRoleRecords(em, entity);
        }
    }


    private void cleanupRoleRecords(EntityManager em, TideRoleDraftEntity mapping) {
        List<String> recordsToRemove = new ArrayList<>(em.createNamedQuery("getUserRoleMappingDraftsByRole", String.class)
                .setParameter("roleId", mapping.getRole().getId())
                .getResultList());

        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", mapping.getRole().getId())
                .executeUpdate();

        recordsToRemove.addAll(em.createNamedQuery("selectIdsForRemoval", String.class)
                .setParameter("role", mapping.getRole())
                .getResultList());
        recordsToRemove.add(mapping.getId());

        em.createNamedQuery("removeDraftRequestsOnRemovalOfRole")
                .setParameter("role", mapping.getRole())
                .executeUpdate();

        recordsToRemove.forEach(id -> em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", id)
                .executeUpdate());
    }
}
