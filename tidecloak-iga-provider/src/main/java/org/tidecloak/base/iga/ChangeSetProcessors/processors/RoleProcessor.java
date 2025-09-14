package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

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
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.removeRoleFromAccessToken;

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

        pendingDrafts.forEach(d -> d.setDeleteStatus(DraftStatus.NULL));
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
                change.getChangeSetId()
        ));

        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                List<TideRoleDraftEntity> entities = em.createNamedQuery("GetRoleDraftEntityByRequestId", TideRoleDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitRoleChangeRequest(realm, entities, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

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
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId(),
                    entity.getChangeRequestId()
            ));
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", action, entity.getId(), entity.getChangeRequestId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

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
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
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
                    ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                            session, em, realm, client, wrappedUser,
                            new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                            ChangeSetType.ROLE, entity);
                    // Note: PH injection also happens in updateAffectedUserContextDrafts and combineChangeRequests.
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session,
                                                AccessProofDetailEntity affectedUserContextDraft,
                                                Set<RoleModel> uniqRoles,
                                                ClientModel client,
                                                TideUserAdapter user,
                                                EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideRoleDraftEntity affectedRoleEntity = em.find(TideRoleDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affectedRoleEntity == null
                || (affectedRoleEntity.getDraftStatus() == DraftStatus.ACTIVE
                && (affectedRoleEntity.getDeleteStatus() == null || affectedRoleEntity.getDeleteStatus().equals(DraftStatus.NULL))))
        {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedRoleEntity);
        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(
                session, realm, client, user, "openid", affectedRoleEntity);

        // Role-draft may store AP compact or bundle in initCert; inject policy markers.
        AuthorizerPolicy ap = tryParseAuthorizerPolicy(affectedRoleEntity.getInitCert());
        if (ap != null) {
            String[] markers = computePolicyMarkers(ap); // full compact hashes + optional legacy via env
            userContextDraft = injectAllowMarkers(userContextDraft, markers, true, true);
            if (ap.payload() != null && ap.payload().threshold != null) {
                userContextDraft = setThresholdIfPresent(userContextDraft, ap.payload().threshold);
            }
        }

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
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideRoleDraftEntity> userRoleEntities,
            EntityManager em) throws IOException, Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        RealmModel realm = session.getContext().getRealm();

        // Group raw AccessProofDetailEntity items by userId and clientId
        Map<UserClientKey, List<AccessProofDetailEntity>> rawMap =
                ChangeSetProcessor.super.groupChangeRequests(userRoleEntities, em);

        Map<String, Map<String, List<AccessProofDetailEntity>>> byUserClient =
                rawMap.entrySet().stream()
                        .flatMap(e -> e.getValue().stream()
                                .map(proof -> Map.entry(e.getKey(), proof)))
                        .collect(Collectors.groupingBy(
                                e -> e.getKey().getUserId(),
                                Collectors.groupingBy(
                                        e -> e.getKey().getClientId(),
                                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                                )));

        // Prefetch all UserEntity instances in one query
        List<String> userIds = new ArrayList<>(byUserClient.keySet());
        Map<String, UserEntity> userById = em.createQuery(
                        "SELECT u FROM UserEntity u WHERE u.id IN :ids", UserEntity.class)
                .setParameter("ids", userIds)
                .getResultList().stream()
                .collect(Collectors.toMap(UserEntity::getId, Function.identity()));

        // Cache ClientModel lookups to avoid repeated realm.getClientById() calls
        Set<String> clientIds = byUserClient.values().stream()
                .flatMap(m -> m.keySet().stream())
                .collect(Collectors.toSet());
        Map<String, ClientModel> clientById = clientIds.stream()
                .map(cid -> Map.entry(cid, realm.getClientById(cid)))
                .filter(e -> e.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        List<ChangesetRequestEntity> results = new ArrayList<>(byUserClient.size());

        // Iterate over each user group to merge proofs and retrieve change requests
        for (var userEntry : byUserClient.entrySet()) {
            String userId = userEntry.getKey();
            UserEntity ue = userById.get(userId);
            UserModel um = session.users().getUserById(realm, userId);

            String combinedRequestId = KeycloakModelUtils.generateId();

            List<AccessProofDetailEntity> toRemoveProofs = new ArrayList<>();
            List<ChangesetRequestEntity> toRemoveRequests = new ArrayList<>();

            // Merge proofs across clients into a single JSON draft
            for (var clientEntry : userEntry.getValue().entrySet()) {
                ClientModel cm = clientById.get(clientEntry.getKey());
                AtomicReference<String> mappingId = new AtomicReference<>();
                AtomicBoolean isFirstRun = new AtomicBoolean(true);

                if (cm == null) continue;
                String combinedProofDraft = null;

                for (var proof : clientEntry.getValue()) {
                    mappingId.set(proof.getChangeRequestKey().getMappingId());
                    TideRoleDraftEntity draft = (TideRoleDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(
                            em, ChangeSetType.ROLE, proof.getChangeRequestKey().getMappingId());

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

                    // Inject policy markers if this draft stores an AP compact/bundle
                    AuthorizerPolicy ap = tryParseAuthorizerPolicy(draft.getInitCert());
                    if (ap != null) {
                        String[] markers = computePolicyMarkers(ap);
                        combinedProofDraft = injectAllowMarkers(combinedProofDraft, markers, true, true);
                        if (ap.payload() != null && ap.payload().threshold != null) {
                            combinedProofDraft = setThresholdIfPresent(combinedProofDraft, ap.payload().threshold);
                        }
                    }

                    toRemoveProofs.add(proof);
                    toRemoveRequests.addAll(em.createNamedQuery(
                                    "getAllChangeRequestsByRecordId",
                                    ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                            .getResultList());

                    if (isFirstRun.get()) isFirstRun.set(false);
                }

                ChangeSetProcessor.super.saveUserContextDraft(
                        session, em, realm, cm, ue,
                        new ChangeRequestKey(mappingId.get(), combinedRequestId),
                        ChangeSetType.ROLE, combinedProofDraft);
            }

            // Remove outdated proofs and their change-request entities
            toRemoveProofs.forEach(em::remove);
            toRemoveRequests.forEach(em::remove);

            // Retrieve the recreated ChangeRequestEntity(ies) for this combinedRequestId
            List<ChangesetRequestEntity> created = em.createNamedQuery(
                            "getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", combinedRequestId)
                    .getResultList();
            results.addAll(created);
        }

        // Flush all pending changes once at the end
        em.flush();

        return results;
    }

    private void commitRoleChangeRequest(RealmModel realm, List<TideRoleDraftEntity> entities, ChangeSetRequest change, EntityManager em) {
        entities.forEach((entity) -> {
            RoleModel role = realm.getRoleById(entity.getRole().getId());
            if (role == null) return;

            if (change.getActionType() == ActionType.CREATE) {
                if(entity.getDraftStatus().equals(DraftStatus.ACTIVE)) return;
                if(entity.getDraftStatus() != DraftStatus.APPROVED){
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);

            } else if (change.getActionType() == ActionType.DELETE) {
                if(entity.getDeleteStatus() != DraftStatus.APPROVED && entity.getDeleteStatus() != DraftStatus.ACTIVE ){
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDeleteStatus(DraftStatus.ACTIVE);
                realm.removeRole(role);
                cleanupRoleRecords(em, entity);
            }
        });
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

    // ===== Helpers: AP parsing (supports bundle) + marker computation + JSON injection =====

    @SuppressWarnings("unchecked")
    private static AuthorizerPolicy tryParseAuthorizerPolicy(String stored) {
        if (stored == null || stored.isBlank()) return null;
        String s = stored.trim();
        try {
            if (s.startsWith("{")) {
                Map<String, String> m = new ObjectMapper().readValue(s, Map.class);
                String compact = m.getOrDefault("auth", m.values().stream().findFirst().orElse(""));
                if (compact == null || compact.isBlank()) return null;
                return AuthorizerPolicy.fromCompact(compact);
            } else {
                return AuthorizerPolicy.fromCompact(s);
            }
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

    /**
     * Primary markers: sha256/sha512 over FULL COMPACT ("h.p.s" UTF-8) if available, else over "h.p".
     * Optional legacy (env): sha256/sha512 over "h.p" and/or payload DLL 'bh'.
     */
    private static String[] computePolicyMarkers(AuthorizerPolicy ap) {
        try {
            List<String> out = new ArrayList<>(4);

            String compactWithSig = safeCompactWithSig(ap);
            byte[] full = compactWithSig.getBytes(StandardCharsets.UTF_8);
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

    private static String safeCompactWithSig(AuthorizerPolicy ap) {
        String s = ap.toCompactStringWithSignature();
        if (s == null || s.isBlank()) s = safeCompactNoSig(ap);
        return s;
    }

    private static String safeCompactNoSig(AuthorizerPolicy ap) {
        String s = ap.toCompactString();
        return (s == null) ? "" : s;
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
