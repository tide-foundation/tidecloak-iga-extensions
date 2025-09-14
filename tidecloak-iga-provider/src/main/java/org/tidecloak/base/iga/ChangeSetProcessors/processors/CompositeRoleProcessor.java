package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideRoleAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ClientUtils.getUniqueClientList;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.RoleUtils.commitDefaultRolesOnInitiation;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.*;

public class CompositeRoleProcessor implements ChangeSetProcessor<TideCompositeRoleMappingDraftEntity> {

    private static final Logger logger = Logger.getLogger(CompositeRoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, ActionType actionType){
        RealmModel realm = session.getContext().getRealm();
        TideRoleAdapter tideRoleAdapter = new TideRoleAdapter(session, realm, em, entity.getComposite());
        tideRoleAdapter.removeChildRoleFromCompositeRoleRecords(entity, actionType);

        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getChangeRequestId());
        accessProofDetailEntities.forEach(em::remove);

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.COMPOSITE_ROLE));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void request(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            logger.debugf("REQUEST start: %s action=%s entityId=%s changeReqId=%s",
                    getClass().getSimpleName(), action, entity.getId(), entity.getChangeRequestId());

            switch (action) {
                case CREATE -> {
                    logger.debugf("CREATE mappingId=%s changeReqId=%s", entity.getId(), entity.getChangeRequestId());
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                }
                case DELETE -> {
                    logger.debugf("DELETE mappingId=%s changeReqId=%s", entity.getId(), entity.getChangeRequestId());
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                }
                default -> {
                    logger.warnf("Unsupported action %s for mappingId=%s changeReqId=%s", action, entity.getId(), entity.getChangeRequestId());
                    throw new IllegalArgumentException("Unsupported action: " + action);
                }
            }

            logger.debugf("REQUEST done: %s entityId=%s changeReqId=%s",
                    getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId());
        } catch (Exception e) {
            logger.errorf(e, "REQUEST error: %s entityId=%s changeReqId=%s action=%s: %s",
                    getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId(), action, e.getMessage());
            throw new RuntimeException("Failed to process COMPOSITE_ROLE request", e);
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debugf("COMMIT start: %s action=%s entityId=%s changeReqId=%s",
                getClass().getSimpleName(), change.getActionType(), entity.getId(), entity.getChangeRequestId());

        RealmModel realm = session.getContext().getRealm();
        Runnable callback = () -> {
            try {
                List<TideCompositeRoleMappingDraftEntity> entities = em.createNamedQuery("GetCompositeRoleMappingDraftEntityByRequestId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId())
                        .getResultList();

                commitCallback(realm, change, entities);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        logger.debugf("COMMIT done: %s entityId=%s changeReqId=%s",
                getClass().getSimpleName(), entity.getId(), entity.getChangeRequestId());
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RoleEntity parentEntity = entity.getComposite();
        RoleEntity childEntity = entity.getChildRole();
        RealmModel realm = session.realms().getRealm(parentEntity.getRealmId());
        RoleModel parentRole = realm.getRoleById(parentEntity.getId());
        RoleModel childRole = realm.getRoleById(childEntity.getId());

        List<TideUserAdapter> activeUsers = session.users().getRoleMembersStream(realm, parentRole).map(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", parentRole.getId())
                    .getResultList();

            if (userRecords == null || userRecords.isEmpty()) {
                return null;
            }
            return new TideUserAdapter(session, realm, em, userEntity);
        }).filter(Objects::nonNull).toList();

        if (activeUsers.isEmpty() || commitDefaultRolesOnInitiation(session, realm, parentEntity, childRole, em)) {
            entity.setDraftStatus(DraftStatus.ACTIVE);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, changeSetRequest, entity, em);
            em.persist(entity);

            ChangesetRequestEntity cr = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), changeSetRequest.getType()));
            if (cr != null) {
                em.remove(cr);
            }
            em.flush();

            List<AccessProofDetailEntity> clientEntities = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndRealm", AccessProofDetailEntity.class)
                    .setParameter("changesetType", ChangeSetType.CLIENT)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            if (parentRole.equals(realm.getDefaultRole())) {
                if (!clientEntities.isEmpty()) {
                    clientEntities.forEach(c -> {
                        try {
                            ClientModel client = realm.getClientById(c.getClientId());
                            String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, false);
                            em.remove(c);
                            ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null,
                                    new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                                    ChangeSetType.CLIENT, defaultFullScopeUserContext);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
                }
            }
        } else {
            List<ClientModel> clientList = getUniqueClientList(session, realm, childRole, em);
            clientList.forEach(client -> {
                for (UserModel user : activeUsers) {
                    try {
                        UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                                session, em, realm, client, wrappedUser,
                                new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                                ChangeSetType.COMPOSITE_ROLE, entity);
                        // NOTE: policy-hash markers are injected later in combineChangeRequests/updateAffectedUserContextDrafts.
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                try {
                    if (parentRole.equals(realm.getDefaultRole())) {
                        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, false);
                        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null,
                                new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                                ChangeSetType.DEFAULT_ROLES, defaultFullScopeUserContext);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, Runnable callback) {
        mapping.setChangeRequestId(KeycloakModelUtils.generateId());
        mapping.setDeleteStatus(DraftStatus.DRAFT);
        mapping.setTimestamp(System.currentTimeMillis());
        processExistingRequest(session, em, session.getContext().getRealm(), mapping, ActionType.DELETE);
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, UserModel user, ClientModel clientModel){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        RoleModel childRole = realm.getRoleById(entity.getChildRole().getId());
        UserContextUtils userContextUtils = new UserContextUtils();

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        if (change.getActionType().equals(ActionType.CREATE)) {
            Set<RoleModel> roleToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), clientModel,
                    clientModel.getClientScopes(true).values().stream(), clientModel.isFullScopeAllowed(), childRole);
            roleToAdd.forEach(r -> addRoleToAccessToken(token, r));
        } else if (change.getActionType().equals(ActionType.DELETE)) {
            List<TideUserRoleMappingDraftEntity> activeDirectRole = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusAndUserId", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("roleId", childRole.getId())
                    .setParameter("userId", user.getId())
                    .getResultList();

            Set<RoleModel> rolesToDelete = expandCompositeRoles(session, Set.of(childRole));
            rolesToDelete.remove(childRole);
            if (activeDirectRole.isEmpty()) {
                rolesToDelete.add(childRole);
            }
            rolesToDelete.forEach(r -> removeRoleFromAccessToken(token, r));
        }

        userContextUtils.normalizeAccessToken(token, true);
        return token;
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session , AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

        RealmModel realm = session.getContext().getRealm();
        TideCompositeRoleMappingDraftEntity affected = em.find(TideCompositeRoleMappingDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affected == null) {
            return;
        }

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, affected);

        if (affectedUserContextDraft.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
            RoleModel childRole = realm.getRoleById(affected.getChildRole().getId());
            ClientModel clientModel = realm.getClientById(affectedUserContextDraft.getClientId());
            String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, clientModel, childRole, em, change.getActionType() == ActionType.DELETE);
            affectedUserContextDraft.setProofDraft(defaultFullScopeUserContext);
            return;
        }

        if ((affected.getDraftStatus() == DraftStatus.ACTIVE && affected.getDeleteStatus() == null)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            affected.setDeleteStatus(DraftStatus.DRAFT);
        } else if (change.getActionType() == ActionType.CREATE) {
            affected.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affected);

        // inject policy markers if the (child/composite) role has an AuthorizerPolicy persisted
        AuthorizerPolicy ap = getPolicyForEitherRole(em, affected.getChildRole().getId(), affected.getComposite().getId());
        if (ap != null) {
            String[] markers = computePolicyMarkers(ap);
            userContextDraft = injectAllowMarkers(userContextDraft, markers, true, true);
            if (ap.payload() != null && ap.payload().threshold != null) {
                userContextDraft = setThresholdIfPresent(userContextDraft, ap.payload().threshold);
            }
        }

        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideCompositeRoleMappingDraftEntity entity) {
        return realm.getRoleById(entity.getChildRole().getId());
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideCompositeRoleMappingDraftEntity> entities,
            EntityManager em) throws IOException, Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        RealmModel realm = session.getContext().getRealm();

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
                AtomicReference<String> mappingId = new AtomicReference<>();
                AtomicBoolean isFirstRun = new AtomicBoolean(true);

                if (cm == null) continue;
                String combinedProofDraft = null;

                for (var proof : clientEntry.getValue()) {
                    mappingId.set(proof.getChangeRequestKey().getMappingId());
                    TideCompositeRoleMappingDraftEntity draft = (TideCompositeRoleMappingDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(
                            em, ChangeSetType.COMPOSITE_ROLE, proof.getChangeRequestKey().getMappingId());

                    if (draft == null) {
                        throw new IllegalStateException("Missing draft for request " + proof.getChangeRequestKey().getMappingId());
                    }

                    draft.setChangeRequestId(combinedRequestId);
                    em.persist(draft);

                    if (combinedProofDraft == null) {
                        combinedProofDraft = proof.getProofDraft();
                    }
                    AccessToken token = objectMapper.readValue(combinedProofDraft, AccessToken.class);
                    combinedProofDraft = combinedTransformedUserContext(session, realm, cm, um, "openid", draft, token);

                    // inject policy markers (PH) if available for the involved role(s)
                    AuthorizerPolicy ap = getPolicyForEitherRole(em, draft.getChildRole().getId(), draft.getComposite().getId());
                    if (ap != null) {
                        String[] markers = computePolicyMarkers(ap);
                        combinedProofDraft = injectAllowMarkers(combinedProofDraft, markers, true, true);
                        if (ap.payload() != null && ap.payload().threshold != null) {
                            combinedProofDraft = setThresholdIfPresent(combinedProofDraft, ap.payload().threshold);
                        }
                    }

                    toRemoveProofs.add(proof);
                    toRemoveRequests.addAll(em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                            .getResultList());

                    if (isFirstRun.get()) {
                        isFirstRun.set(false);
                    }
                }

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue,
                        new ChangeRequestKey(mappingId.get(), combinedRequestId),
                        ChangeSetType.COMPOSITE_ROLE, combinedProofDraft);
            }

            toRemoveProofs.forEach(em::remove);
            toRemoveRequests.forEach(em::remove);

            List<ChangesetRequestEntity> created = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", combinedRequestId)
                    .getResultList();
            results.addAll(created);
        }

        em.flush();
        return results;
    }

    private void commitCallback(RealmModel realm, ChangeSetRequest change, List<TideCompositeRoleMappingDraftEntity> entities){
        entities.forEach(entity -> {
            if (change.getActionType() == ActionType.CREATE) {
                if (entity.getDraftStatus() == DraftStatus.ACTIVE) return;
                if (entity.getDraftStatus() != DraftStatus.APPROVED) {
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);
            } else if (change.getActionType() == ActionType.DELETE) {
                if (entity.getDeleteStatus() != DraftStatus.APPROVED && entity.getDeleteStatus() != DraftStatus.ACTIVE) {
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDeleteStatus(DraftStatus.ACTIVE);
                RoleModel composite = realm.getRoleById(entity.getComposite().getId());
                RoleModel child = realm.getRoleById(entity.getChildRole().getId());
                composite.removeCompositeRole(child);
            }
        });
    }

    private void processExistingRequest(KeycloakSession session, EntityManager em, RealmModel realm, TideCompositeRoleMappingDraftEntity compositeRoleEntity, ActionType action) {
        RoleEntity parentEntity = compositeRoleEntity.getComposite();
        RoleEntity childEntity = compositeRoleEntity.getChildRole();
        RoleModel parentRole = session.getContext().getRealm().getRoleById(parentEntity.getId());
        RoleModel childRole = session.getContext().getRealm().getRoleById(childEntity.getId());

        List<TideUserAdapter> users = session.users().getRoleMembersStream(realm, parentRole).map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .setParameter("user", userEntity)
                            .setParameter("roleId", parentRole.getId())
                            .getResultList();

                    if (userRecords.isEmpty()) {
                        return null;
                    }
                    return new TideUserAdapter(session, realm, em, userEntity);
                })
                .filter(Objects::nonNull)
                .toList();

        if (users.isEmpty()) {
            return;
        }

        List<ClientModel> clientList = getUniqueClientList(session, realm, childRole, em);
        clientList.forEach(client -> {
            try {
                users.forEach(user -> {
                    UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                    try {
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                                session, em, realm, client, wrappedUser,
                                new ChangeRequestKey(compositeRoleEntity.getId(), compositeRoleEntity.getChangeRequestId()),
                                ChangeSetType.COMPOSITE_ROLE, compositeRoleEntity);
                        // NOTE: PH injection will happen in combineChangeRequests/updateAffectedUserContextDrafts.
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
                if (parentRole.equals(realm.getDefaultRole())) {
                    String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, true);
                    ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null,
                            new ChangeRequestKey(compositeRoleEntity.getId(), compositeRoleEntity.getChangeRequestId()),
                            ChangeSetType.DEFAULT_ROLES, defaultFullScopeUserContext);
                }
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, RoleModel childRole, EntityManager em, Boolean isDelete) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);

        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client,
                client.getClientScopes(true).values().stream(), client.isFullScopeAllowed(), childRole);
        rolesToAdd.forEach(r -> {
            if (realm.getName().equalsIgnoreCase(Config.getAdminRealm())) {
                addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
            } else {
                addRoleToAccessToken(accessToken, r);
            }
        });

        if (clients.contains(client.getClientId())) {
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username"), client.isFullScopeAllowed());
        } else {
            if (isDelete) {
                Set<RoleModel> rolesToDelete = expandCompositeRoles(session, Set.of(childRole));
                rolesToDelete.add(childRole);
                rolesToDelete.forEach(r -> {
                    if (realm.getName().equalsIgnoreCase(Config.getAdminRealm())) {
                        removeRoleFromAccessTokenMasterRealm(accessToken, r, realm, em);
                    } else {
                        removeRoleFromAccessToken(accessToken, r);
                    }
                });
            }
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username"), client.isFullScopeAllowed());
        }
    }

    // ===== Helpers: fetch AP (supports bundle), compute PH markers, inject into user-context =====

    private static AuthorizerPolicy getPolicyForEitherRole(EntityManager em, String childRoleId, String compositeRoleId) {
        AuthorizerPolicy ap = getPolicyForRole(em, childRoleId);
        if (ap != null) return ap;
        return getPolicyForRole(em, compositeRoleId);
    }

    @SuppressWarnings("unchecked")
    private static AuthorizerPolicy getPolicyForRole(EntityManager em, String roleId) {
        try {
            RoleEntity re = em.find(RoleEntity.class, roleId);
            if (re == null) return null;
            List<TideRoleDraftEntity> roleDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                    .setParameter("role", re).getResultList();
            if (roleDrafts.isEmpty()) return null;
            String stored = roleDrafts.get(0).getInitCert(); // column name retained; now stores AP compact or bundle
            if (stored == null || stored.isBlank()) return null;

            String compact = stored.trim();
            if (compact.startsWith("{")) {
                // bundle case: {"auth":"<h.p[.s]>","sign":"<h.p[.s]>"} – prefer "auth"
                Map<String, String> m = new ObjectMapper().readValue(compact, Map.class);
                compact = m.getOrDefault("auth", m.values().stream().findFirst().orElse(""));
            }
            if (compact.isBlank()) return null;
            return AuthorizerPolicy.fromCompact(compact);
        } catch (Exception ignore) {
            return null;
        }
    }

    private static boolean injectDataBhLegacy() {
        String v = System.getenv("INJECT_DATA_BH_LEGACY");
        return v != null && v.equalsIgnoreCase("true");
    }

    private static boolean injectDllBhLegacy() {
        String v = System.getenv("INJECT_DLL_BH_LEGACY");
        return v != null && v.equalsIgnoreCase("true");
    }

    /** Primary markers: sha256/sha512 over FULL COMPACT if available ("h.p.s"), else over "h.p".
     *  Optional legacy: over "h.p" and/or payload DLL 'bh'. */
    private static String[] computePolicyMarkers(AuthorizerPolicy ap) {
        try {
            List<String> out = new ArrayList<>(4);

            // try full compact with signature via reflection (if provided by the model)
            String fullCompact = tryCompactWithSignature(ap);
            if (fullCompact == null || fullCompact.isBlank()) {
                fullCompact = safeCompactNoSig(ap);
            }
            byte[] full = fullCompact.getBytes(StandardCharsets.UTF_8);
            out.add("sha256:" + toHexUpper(MessageDigest.getInstance("SHA-256").digest(full)));
            out.add("sha512:" + toHexUpper(MessageDigest.getInstance("SHA-512").digest(full)));

            if (injectDataBhLegacy()) {
                String dataOnly = safeCompactNoSig(ap);
                byte[] data = dataOnly.getBytes(StandardCharsets.UTF_8);
                out.add("sha256:" + toHexUpper(MessageDigest.getInstance("SHA-256").digest(data)));
                out.add("sha512:" + toHexUpper(MessageDigest.getInstance("SHA-512").digest(data)));
            }
            if (injectDllBhLegacy() && ap.payload() != null && ap.payload().bh != null && !ap.payload().bh.isBlank()) {
                out.add(ap.payload().bh);
            }
            return out.toArray(new String[0]);
        } catch (Exception e) {
            throw new RuntimeException("Failed computing policy markers", e);
        }
    }

    private static String tryCompactWithSignature(AuthorizerPolicy ap) {
        try {
            var m = ap.getClass().getMethod("toCompactStringWithSignature");
            Object v = m.invoke(ap);
            return v != null ? v.toString() : null;
        } catch (Exception ignore) {
            return null;
        }
    }

    private static String safeCompactNoSig(AuthorizerPolicy ap) {
        try {
            String s = ap.toCompactString();
            return (s == null) ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    private static String injectAllowMarkers(String userContextJson, String[] markers, boolean includeAuth, boolean includeSign) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root  = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = root.with("allow");
            if (includeAuth) appendAllIfMissing(allow.withArray("auth"), markers);
            if (includeSign) appendAllIfMissing(allow.withArray("sign"), markers);
            return om.writeValueAsString(root);
        } catch (Exception e) {
            throw new RuntimeException("injectAllowMarkers failed", e);
        }
    }

    private static void appendAllIfMissing(ArrayNode arr, String[] values) {
        Set<String> existing = new HashSet<>();
        for (int i = 0; i < arr.size(); i++) existing.add(arr.get(i).asText());
        for (String v : values) if (!existing.contains(v)) arr.add(v);
    }

    private static String setThresholdIfPresent(String userContextJson, int threshold) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            root.put("threshold", threshold);
            return om.writeValueAsString(root);
        } catch (Exception e) {
            return userContextJson; // tolerate schema differences
        }
    }

    private static String toHexUpper(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
