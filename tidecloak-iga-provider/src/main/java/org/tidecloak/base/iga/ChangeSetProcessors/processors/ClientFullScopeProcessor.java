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
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.*;

public class ClientFullScopeProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientFullScopeProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        if (!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)) {
            entity.setFullScopeDisabled(DraftStatus.NULL);
        } else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)) {
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // remove pending drafts for FULLSCOPE + DEFAULT_USER_CONTEXT
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery(
                        "getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getId())
                .setParameter("changesetTypes", List.of(ChangeSetType.CLIENT_FULLSCOPE, ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT))
                .getResultList();
        pendingChanges.forEach(em::remove);
        em.flush();

        ChangesetRequestEntity cr = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.CLIENT_FULLSCOPE));
        if (cr != null) {
            em.remove(cr);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debugf("Starting workflow: COMMIT. Processor=%s Action=%s EntityID=%s",
                getClass().getSimpleName(), change.getActionType(), entity.getId());

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = new TideClientAdapter(realm, em, session, entity.getClient());

        Runnable callback = () -> {
            try {
                List<TideClientDraftEntity> entities = em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitCallback(change, entities, client, em);
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        logger.debugf("Successfully processed COMMIT. Processor=%s MappingID=%s",
                getClass().getSimpleName(), entity.getId());
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            logger.debugf("Starting workflow: REQUEST. Processor=%s Action=%s EntityID=%s",
                    getClass().getSimpleName(), action, entity.getId());

            RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            switch (action) {
                case CREATE -> {
                    logger.debugf("Initiating CREATE (enable fullscope) MappingID=%s", entity.getId());
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    if (!isIGAEnabled) {
                        if (entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)) {
                            entity.setFullScopeDisabled(DraftStatus.NULL);
                        }
                        if (callback != null) callback.run();
                    }
                }
                case DELETE -> {
                    logger.debugf("Initiating DELETE (disable fullscope) MappingID=%s", entity.getId());
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    if (!isIGAEnabled) {
                        if (entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)) {
                            entity.setFullScopeEnabled(DraftStatus.NULL);
                        }
                        if (callback != null) callback.run();
                    }
                }
                default -> {
                    logger.warnf("Unsupported action %s for MappingID=%s", action, entity.getId());
                    throw new IllegalArgumentException("Unsupported action: " + action);
                }
            }
        } catch (Exception e) {
            logger.errorf(e, "Error in REQUEST. Processor=%s MappingID=%s Action=%s: %s",
                    getClass().getSimpleName(), entity.getId(), action, e.getMessage());
            throw new RuntimeException("Failed to process CLIENT_FULLSCOPE request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        entity.setFullScopeEnabled(DraftStatus.DRAFT);
        em.persist(entity);
        em.flush();

        // also produce default user context under fullscope=enabled
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity, ChangeSetType.CLIENT_FULLSCOPE);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(
                session, em, realm, client, null,
                new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);
        em.flush();

        // generate transformed contexts for all users in realm
        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
        for (UserModel user : usersInRealm) {
            try {
                List<AccessProofDetailEntity> pending = em.createNamedQuery(
                                "getProofDetailsForDraftByChangeSetTypeAndIdAndUser", AccessProofDetailEntity.class)
                        .setParameter("recordId", entity.getId())
                        .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                        .setParameter("userId", user.getId())
                        .getResultList();
                if (pending != null && !pending.isEmpty()) continue;

                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, wrappedUser,
                        new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                        ChangeSetType.CLIENT_FULLSCOPE, entity);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();

        if (usersInRealm.isEmpty()) {
            if (callback != null) callback.run();
            approveFullScope(entity, false);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, changeSetRequest, entity, em);
            return;
        }

        entity.setFullScopeDisabled(DraftStatus.DRAFT);
        em.merge(entity);
        em.flush();

        // also update default user context to reflect fullscope disabled
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(
                session, em, realm, client, null,
                new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);
        em.flush();

        for (UserModel user : usersInRealm) {
            List<AccessProofDetailEntity> pending = em.createNamedQuery(
                            "getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                    .setParameter("recordId", entity.getId())
                    .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                    .getResultList();
            if (pending != null && !pending.isEmpty()) continue;

            try {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, user,
                        new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                        ChangeSetType.CLIENT_FULLSCOPE, entity);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        em.flush();
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideClientDraftEntity affected = em.find(TideClientDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affected == null ||
                isValidStatusPair(affected.getFullScopeDisabled(), affected.getFullScopeEnabled()) ||
                isValidStatusPair(affected.getFullScopeEnabled(), affected.getFullScopeDisabled())) {
            return;
        }

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, affected);

        if (change.getActionType() == ActionType.DELETE) {
            affected.setFullScopeDisabled(DraftStatus.DRAFT);
        } else if (change.getActionType() == ActionType.CREATE) {
            affected.setFullScopeEnabled(DraftStatus.DRAFT);
        }

        // generate transformed user context under the current fullscope toggle
        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(
                session, realm, client, user, "openid", affected);
        affectedUserContextDraft.setProofDraft(userContextDraft);
        em.flush();
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null;
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideClientDraftEntity entity, UserModel user, ClientModel clientModel) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());

        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> activeRoles = userContextUtils.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        Set<RoleModel> roleSet = UserContextUtils.getAccess(
                activeRoles,
                client,
                client.getClientScopes(true).values().stream(),
                change.getActionType().equals(ActionType.CREATE));

        if (change.getActionType().equals(ActionType.DELETE)) {
            if (token.getRealmAccess() != null && token.getRealmAccess().getRoles() != null) {
                token.getRealmAccess().getRoles().clear();
            }
            if (token.getResourceAccess() != null) token.getResourceAccess().clear();
        }

        roleSet.forEach(role -> addRoleToAccessToken(token, role));

        userContextUtils.normalizeAccessToken(token, client.isFullScopeAllowed());
        return token;
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideClientDraftEntity> userRoleEntities,
            EntityManager em) throws IOException, Exception {

        ObjectMapper objectMapper = new ObjectMapper();
        RealmModel realm = session.getContext().getRealm();

        Map<UserClientKey, List<AccessProofDetailEntity>> rawMap =
                ChangeSetProcessor.super.groupChangeRequests(userRoleEntities, em);

        Map<String, Map<String, List<AccessProofDetailEntity>>> byUserClient =
                rawMap.entrySet().stream()
                        .flatMap(e -> e.getValue().stream().map(proof -> Map.entry(e.getKey(), proof)))
                        .collect(Collectors.groupingBy(
                                e -> e.getKey().getUserId(),
                                Collectors.groupingBy(
                                        e -> e.getKey().getClientId(),
                                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                                )));

        List<String> userIds = new ArrayList<>(byUserClient.keySet());
        Map<String, UserEntity> userById = em.createQuery(
                        "SELECT u FROM UserEntity u WHERE u.id IN :ids", UserEntity.class)
                .setParameter("ids", userIds)
                .getResultList().stream()
                .collect(Collectors.toMap(UserEntity::getId, Function.identity()));

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
                            em, ChangeSetType.CLIENT_FULLSCOPE, proof.getChangeRequestKey().getMappingId());

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
                        ChangeSetType.CLIENT_FULLSCOPE, combinedProofDraft);
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

    private void commitCallback(ChangeSetRequest change, List<TideClientDraftEntity> entities, ClientModel clientModel, EntityManager em) {
        entities.forEach(entity -> {
            if (change.getActionType() == ActionType.CREATE) {
                if (entity.getFullScopeEnabled() != DraftStatus.APPROVED && entity.getFullScopeEnabled() != DraftStatus.ACTIVE) {
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setFullScopeEnabled(DraftStatus.ACTIVE);
                entity.setFullScopeDisabled(DraftStatus.NULL);
                clientModel.setFullScopeAllowed(true);
            } else if (change.getActionType() == ActionType.DELETE) {
                if (entity.getFullScopeDisabled() != DraftStatus.APPROVED && entity.getFullScopeDisabled() != DraftStatus.ACTIVE) {
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setFullScopeDisabled(DraftStatus.ACTIVE);
                entity.setFullScopeEnabled(DraftStatus.NULL);
                clientModel.setFullScopeAllowed(false);
            }

            ChangesetRequestEntity cre = em.find(ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(change.getChangeSetId(), ChangeSetType.CLIENT));
            if (entity.getDraftStatus().equals(DraftStatus.DRAFT) && cre != null) {
                entity.setDraftStatus(DraftStatus.ACTIVE);

                List<AccessProofDetailEntity> pending = em.createNamedQuery(
                                "getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                        .setParameter("recordId", entity.getId())
                        .setParameter("changesetTypes", List.of(ChangeSetType.CLIENT))
                        .getResultList();
                pending.forEach(em::remove);
                em.remove(cre);
            }
        });
    }

    private void approveFullScope(TideClientDraftEntity clientFullScopeStatuses, boolean isEnabled) {
        if (isEnabled) {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
        } else {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
        }
    }

    private boolean isValidStatusPair(DraftStatus activeStatus, DraftStatus inactiveStatus) {
        return activeStatus == DraftStatus.ACTIVE &&
                (inactiveStatus == null || inactiveStatus == DraftStatus.NULL);
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em, ChangeSetRequest change) throws Exception {
        List<String> specialClients = List.of(
                Constants.ADMIN_CLI_CLIENT_ID,
                Constants.ADMIN_CONSOLE_CLIENT_ID,
                Constants.ACCOUNT_CONSOLE_CLIENT_ID
        );

        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        try {
            AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
            boolean isFullscope = change.getActionType().equals(ActionType.CREATE);

            if (specialClients.contains(client.getClientId())) {
                accessToken.subject(null);
                return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
            }

            Set<RoleModel> rolesToAdd = getAllAccess(
                    session,
                    Set.of(realm.getDefaultRole()),
                    client,
                    client.getClientScopes(true).values().stream(),
                    isFullscope,
                    null);

            rolesToAdd.forEach(r -> {
                if (realm.getName().equalsIgnoreCase(Config.getAdminRealm())) {
                    addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
                } else {
                    addRoleToAccessToken(accessToken, r);
                }
            });

            accessToken.subject(null);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
        } finally {
            session.users().removeUser(realm, dummyUser);
        }
    }
}
