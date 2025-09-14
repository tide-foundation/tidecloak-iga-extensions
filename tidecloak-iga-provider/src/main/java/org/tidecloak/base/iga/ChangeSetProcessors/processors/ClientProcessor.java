package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.*;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;

public class ClientProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        // reset toggle drafts if they weren’t actually ACTIVE
        if (!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)) {
            entity.setFullScopeDisabled(DraftStatus.NULL);
        } else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)) {
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // remove pending CLIENT proofs for this change-set
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery(
                        "getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.CLIENT)
                .getResultList();
        pendingChanges.forEach(em::remove);
        em.flush();

        // remove the changeset request shell if any
        ChangesetRequestEntity cr = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.CLIENT));
        if (cr != null) {
            em.remove(cr);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debugf("Starting workflow: COMMIT. Processor=%s Action=%s EntityID=%s ChangeSetID=%s",
                getClass().getSimpleName(), change.getActionType(), entity.getId(), change.getChangeSetId());

        RealmModel realm = session.getContext().getRealm();
        Runnable callback = () -> {
            try {
                List<TideClientDraftEntity> entities = em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId())
                        .getResultList();
                commitDefaultUserContext(realm, entities, change);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        logger.debugf("Successfully processed COMMIT. Processor=%s EntityID=%s ChangeSetID=%s",
                getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId());
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            logger.debugf("Starting workflow: REQUEST. Processor=%s Action=%s EntityID=%s ChangeReqID=%s",
                    getClass().getSimpleName(), action, entity.getId(), entity.getChangeRequestId());

            switch (action) {
                case CREATE -> {
                    logger.debugf("Initiating CREATE for MappingID=%s", entity.getId());
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                }
                case DELETE -> {
                    logger.debug("Client Processor has no implementation for DELETE.");
                    // if ever needed: ChangeSetProcessor.super.createChangeRequestEntity(...)
                }
                default -> {
                    logger.warnf("Unsupported action type %s for MappingID=%s", action, entity.getId());
                    throw new IllegalArgumentException("Unsupported action: " + action);
                }
            }

            logger.debugf("Successfully processed REQUEST. Processor=%s MappingID=%s ChangeReqID=%s",
                    getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId());
        } catch (Exception e) {
            logger.errorf(e,
                    "Error in REQUEST. Processor=%s MappingID=%s ChangeReqID=%s Action=%s: %s",
                    getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId(), action, e.getMessage());
            throw new RuntimeException("Failed to process CLIENT request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
        ClientModel client = realm.getClientById(entity.getClient().getId());

        // generate the realm default user context for this client (no PH/BH injection here)
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em);

        ChangeSetProcessor.super.saveUserContextDraft(
                session, em, realm, client, null,
                new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                ChangeSetType.CLIENT, defaultFullScopeUserContext);
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) {
        // no-op (not supported)
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.realms().getRealm(userContextDraft.getRealmId());
        String defaultUserContext = generateRealmDefaultUserContext(session, realm, client, em);

        // replace the draft with a freshly generated default context
        em.remove(userContextDraft);
        ChangeSetProcessor.super.saveUserContextDraft(
                session, em, session.getContext().getRealm(), client, null,
                userContextDraft.getChangeRequestKey(), ChangeSetType.CLIENT, defaultUserContext);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null; // CLIENT toggles don’t reference a single role
    }

    private void commitDefaultUserContext(RealmModel realm, List<TideClientDraftEntity> entities, ChangeSetRequest change) {
        entities.forEach(entity -> {
            ClientModel clientModel = realm.getClientByClientId(entity.getClient().getClientId());
            if (clientModel == null) return;

            if (change.getActionType() == ActionType.CREATE) {
                if (entity.getDraftStatus() != DraftStatus.APPROVED && entity.getDraftStatus() != DraftStatus.ACTIVE) {
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);
            } else if (change.getActionType() == ActionType.DELETE) {
                throw new RuntimeException("CLIENT has no implementation for DELETE");
            }
        });
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideClientDraftEntity> entities,
            EntityManager em) throws IOException, Exception {

        ObjectMapper objectMapper = new ObjectMapper();
        RealmModel realm = session.getContext().getRealm();

        // group proofs by user + client
        Map<UserClientKey, List<AccessProofDetailEntity>> rawMap =
                ChangeSetProcessor.super.groupChangeRequests(entities, em);

        Map<String, Map<String, List<AccessProofDetailEntity>>> byUserClient =
                rawMap.entrySet().stream()
                        .flatMap(e -> e.getValue().stream().map(proof -> Map.entry(e.getKey(), proof)))
                        .collect(Collectors.groupingBy(
                                e -> e.getKey().getUserId(),
                                Collectors.groupingBy(
                                        e -> e.getKey().getClientId(),
                                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                                )));

        // prefetch users
        List<String> userIds = new ArrayList<>(byUserClient.keySet());
        Map<String, UserEntity> userById = em.createQuery(
                        "SELECT u FROM UserEntity u WHERE u.id IN :ids", UserEntity.class)
                .setParameter("ids", userIds)
                .getResultList().stream()
                .collect(Collectors.toMap(UserEntity::getId, Function.identity()));

        // cache clients
        Set<String> clientIds = byUserClient.values().stream()
                .flatMap(m -> m.keySet().stream())
                .collect(Collectors.toSet());
        Map<String, ClientModel> clientById = clientIds.stream()
                .map(cid -> Map.entry(cid, realm.getClientById(cid)))
                .filter(e -> e.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        List<ChangesetRequestEntity> results = new ArrayList<>(byUserClient.size());

        for (var userEntry : byUserClient.entrySet()) {
            String userId = userEntry.getKey();
            UserEntity ue = userById.get(userId);
            UserModel um = session.users().getUserById(realm, userId);

            String combinedRequestId = KeycloakModelUtils.generateId();
            List<AccessProofDetailEntity> toRemoveProofs = new ArrayList<>();
            List<ChangesetRequestEntity> toRemoveRequests = new ArrayList<>();

            for (var clientEntry : userEntry.getValue().entrySet()) {
                ClientModel cm = clientById.get(clientEntry.getKey());
                if (cm == null) continue;

                AtomicReference<String> mappingId = new AtomicReference<>();
                AtomicBoolean isFirstRun = new AtomicBoolean(true);
                String combinedProofDraft = null;

                for (var proof : clientEntry.getValue()) {
                    mappingId.set(proof.getChangeRequestKey().getMappingId());
                    TideClientDraftEntity draft = (TideClientDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(
                            em, ChangeSetType.CLIENT, proof.getChangeRequestKey().getMappingId());

                    if (draft == null) {
                        throw new IllegalStateException("Missing draft for request " + proof.getChangeRequestKey().getMappingId());
                    }

                    draft.setChangeRequestId(combinedRequestId);
                    em.persist(draft);

                    if (combinedProofDraft == null) {
                        combinedProofDraft = proof.getProofDraft();
                    }
                    AccessToken token = objectMapper.readValue(combinedProofDraft, AccessToken.class);
                    combinedProofDraft = combinedTransformedUserContext(
                            session, realm, cm, um, "openid", draft, token);

                    toRemoveProofs.add(proof);
                    toRemoveRequests.addAll(em.createNamedQuery(
                                    "getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                            .getResultList());

                    isFirstRun.set(false);
                }

                ChangeSetProcessor.super.saveUserContextDraft(
                        session, em, realm, cm, ue,
                        new ChangeRequestKey(mappingId.get(), combinedRequestId),
                        ChangeSetType.CLIENT, combinedProofDraft);
            }

            toRemoveProofs.forEach(em::remove);
            toRemoveRequests.forEach(em::remove);

            List<ChangesetRequestEntity> created = em.createNamedQuery(
                            "getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", combinedRequestId)
                    .getResultList();
            results.addAll(created);
        }

        em.flush();
        return results;
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em) throws Exception {
        // SPECIAL clients: strip subject & keep minimal context
        List<String> specialClients = List.of(
                Constants.ADMIN_CLI_CLIENT_ID,
                Constants.ADMIN_CONSOLE_CLIENT_ID,
                Constants.ACCOUNT_CONSOLE_CLIENT_ID
        );

        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        try {
            AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);

            if (specialClients.contains(client.getClientId())) {
                accessToken.subject(null);
                return ChangeSetProcessor.super.cleanAccessToken(
                        accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
            }

            // collect all reachable access (no PH/BH here — done centrally elsewhere if needed)
            Set<RoleModel> rolesToAdd = getAllAccess(
                    session,
                    Set.of(realm.getDefaultRole()),
                    client,
                    client.getClientScopes(true).values().stream(),
                    client.isFullScopeAllowed(),
                    null);

            rolesToAdd.forEach(r -> {
                if (realm.getName().equalsIgnoreCase(Config.getAdminRealm())) {
                    addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
                } else {
                    addRoleToAccessToken(accessToken, r);
                }
            });

            accessToken.subject(null);
            return ChangeSetProcessor.super.cleanAccessToken(
                    accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
        } finally {
            session.users().removeUser(realm, dummyUser);
        }
    }
}
