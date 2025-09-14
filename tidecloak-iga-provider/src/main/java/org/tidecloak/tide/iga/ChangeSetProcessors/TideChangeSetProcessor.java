package org.tidecloak.tide.iga.ChangeSetProcessors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.midgard.Serialization.Tools;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.AdminAuthorizerBuilder;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.ModelRequest;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.shared.utils.JsonSorter;
import org.keycloak.representations.AccessToken;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDrafts;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDraftsForRealm;

/**
 * Tide-side extension:
 *  - builds Admin:2 requests
 *  - injects POLICY HASH (ph) into allow.{auth,sign} for admin contexts
 *  - remains backward-compatible with legacy DLL BH (bh) when reading/ordering contexts
 */
public class TideChangeSetProcessor<T> implements ChangeSetProcessor<T> {

    @Override
    public void updateAffectedUserContexts(KeycloakSession session, RealmModel realm, ChangeSetRequest change, T entity, EntityManager em) throws Exception {
        Map<ChangeRequestKey, List<AccessProofDetailEntity>> groupedProofDetails = getUserContextDraftsForRealm(em, realm.getId()).stream()
                .filter(proof -> !Objects.equals(proof.getChangeRequestKey().getChangeRequestId(), change.getChangeSetId()))
                .sorted(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed())
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getChangeRequestKey));

        groupedProofDetails.forEach((changeRequestKey, details) -> {
            try {
                List<org.midgard.models.UserContext.UserContext> userContexts = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", changeRequestKey.getChangeRequestId())
                        .getResultStream()
                        .map(p -> new org.midgard.models.UserContext.UserContext(p.getProofDraft()))
                        .collect(Collectors.toList());

                if (userContexts.isEmpty()) return;

                // Admins = any context with at least one sha256:* in allow.{auth|sign} (ph or legacy bh)
                List<org.midgard.models.UserContext.UserContext> admins = userContexts.stream()
                        .filter(uc -> isAllowAnySha256(uc.ToString()))
                        .toList();
                List<org.midgard.models.UserContext.UserContext> normals = userContexts.stream()
                        .filter(uc -> !isAllowAnySha256(uc.ToString()))
                        .toList();

                List<org.midgard.models.UserContext.UserContext> orderedContext = Stream.concat(admins.stream(), normals.stream()).toList();
                int normalCount = normals.size();

                org.midgard.models.RequestExtensions.UserContextSignRequest updatedReq =
                        new org.midgard.models.RequestExtensions.UserContextSignRequest("Admin:2");
                updatedReq.SetUserContexts(orderedContext.toArray(new org.midgard.models.UserContext.UserContext[0]));
                updatedReq.SetNumberOfUserContexts(normalCount);

                ChangeSetType changeSetType;
                if (details.get(0).getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
                    changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
                } else if (details.get(0).getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
                    changeSetType = ChangeSetType.COMPOSITE_ROLE;
                } else {
                    changeSetType = details.get(0).getChangesetType();
                }

                ChangesetRequestEntity cre =
                        ChangesetRequestAdapter.getChangesetRequestEntity(session, changeRequestKey.getChangeRequestId(), changeSetType);
                if (cre != null) {
                    cre.setDraftRequest(Base64.getEncoder().encodeToString(updatedReq.GetDraft()));
                }
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, T entity, EntityManager em, Runnable commitCallback) throws Exception {
        String realmId = session.getContext().getRealm().getId();
        List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, change.getChangeSetId(), change.getType());
        if (userContextDrafts.isEmpty()) {
            throw new Exception("No user context drafts found for this change set id, " + change.getChangeSetId());
        }

        for (AccessProofDetailEntity userContextDraft : userContextDrafts) {
            try {
                UserEntity userEntity = userContextDraft.getUser();
                TideUserAdapter affectedUser = TideEntityUtils.toTideUserAdapter(userEntity, session, session.realms().getRealm(userContextDraft.getRealmId()));
                commitUserContextToDatabase(session, userContextDraft, em);
                em.remove(userContextDraft);
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException("Error processing user context draft: " + e.getMessage(), e);
            }
        }

        if (commitCallback != null) commitCallback.run();

        ChangesetRequestEntity changesetRequestEntity =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(change.getChangeSetId(), change.getType()));
        if (changesetRequestEntity != null) em.remove(changesetRequestEntity);

        List<Map.Entry<ChangesetRequestEntity, TideClientDraftEntity>> reqAndDrafts =
                em.createNamedQuery("getAllChangeRequestsByChangeSetType", ChangesetRequestEntity.class)
                        .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                        .getResultStream()
                        .flatMap(cr -> {
                            List<TideClientDraftEntity> drafts = em.createNamedQuery(
                                            "GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                                    .setParameter("requestId", cr.getChangesetRequestId())
                                    .getResultList();

                            List<TideClientDraftEntity> valid = drafts.stream()
                                    .filter(d -> d.getClient().getRealmId().equalsIgnoreCase(realmId))
                                    .collect(Collectors.toList());

                            if (valid.isEmpty()) {
                                em.remove(cr);
                                return Stream.empty();
                            }
                            return valid.stream().map(d -> new AbstractMap.SimpleEntry<>(cr, d));
                        })
                        .collect(Collectors.toList());

        ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();

        reqAndDrafts.forEach(entry -> {
            ChangesetRequestEntity req = entry.getKey();
            TideClientDraftEntity draft = entry.getValue();
            if (draft == null) return;

            ChangeSetRequest c = getChangeSetRequestFromEntity(session, draft, ChangeSetType.CLIENT_FULLSCOPE);

            req.getAdminAuthorizations().clear();
            em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", req.getChangesetRequestId())
                    .getResultStream()
                    .forEach(em::remove);
            em.remove(req);

            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, c.getActionType().equals(ActionType.DELETE), c.getActionType(), ChangeSetType.CLIENT_FULLSCOPE);
            try {
                changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT_FULLSCOPE)
                        .executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
            } catch (Exception e) {
                throw new RuntimeException("Error executing workflow for request ID: " + req.getChangesetRequestId(), e);
            }
        });

        em.flush();
    }

    /**
     * Save a UserContext draft. We now inject POLICY HASH (ph) into allow.{auth,sign}
     * for admin contexts. We still order contexts by "has any sha256:*" to be backward-compatible.
     */
    @Override
    public void saveUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm, ClientModel clientModel,
                                     UserEntity user, ChangeRequestKey changeRequestKey, ChangeSetType type, String proofDraft) throws Exception {

        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, changeRequestKey.getChangeRequestId(), type);
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

        boolean isTideAdminRole = false;
        boolean isUnassignRole = false;
        UserModel originalUser = null;

        // We will compute ph from the compact AP ("h64.p64") if applicable
        String policyCompact = null;
        String policyHashPh = null; // sha256:HEX( header.payload )

        if (type.equals(ChangeSetType.USER_ROLE)) {
            TideUserRoleMappingDraftEntity roleMapping =
                    (TideUserRoleMappingDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, type, changeRequestKey.getMappingId());
            if (roleMapping == null) {
                throw new Exception("Invalid request, no user role mapping draft entity found for record ID: " + changeRequestKey.getChangeRequestId());
            }

            List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                    .setParameter("roleId", roleMapping.getRoleId())
                    .getResultList();
            if (tideRoleDraftEntity.isEmpty()) {
                throw new Exception("Invalid request, no role draft entity found for role ID: " + roleMapping.getRoleId());
            }

            isTideAdminRole = (tideRole != null && roleMapping.getRoleId().equals(tideRole.getId()));

            RoleInitializerCertificateDraftEntity roleInitCertDraft =
                    org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert(session, changeRequestKey.getChangeRequestId());
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, roleMapping);
            isUnassignRole = changeSetRequest.getActionType().equals(ActionType.DELETE);
            originalUser = session.users().getUserById(realm, roleMapping.getUser().getId());


            if(componentModel != null){
                List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                        .setParameter("ID", componentModel.getId())
                        .setParameter("types", List.of("firstAdmin", "multiAdmin")).getResultList();
            // Which AP to use for BH?
            // 1) If this changeset created a new AP draft, use that
            if (roleInitCertDraft != null) {
                policyCompact = unwrapCompactOrFirst(roleInitCertDraft.getInitCert());
            } else if (isTideAdminRole) {
                RoleEntity roleRef = em.getReference(RoleEntity.class, tideRole.getId());
                TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                        .setParameter("role", roleRef)
                        .getSingleResult();
                policyCompact = unwrapCompactOrFirst(tideRoleEntity.getInitCert());
            }

            if (policyCompact != null && !policyCompact.isBlank()) {
                policyHashPh = computePolicyHashFromCompact(policyCompact); // sha256:HEX of header.payload bytes
            }
        }

        List<org.midgard.models.UserContext.UserContext> userContexts = new ArrayList<>();
        int normalCount = 0;

        ObjectMapper om = new ObjectMapper();

        for (AccessProofDetailEntity p : proofDetails) {
            org.midgard.models.UserContext.UserContext uc = new org.midgard.models.UserContext.UserContext(p.getProofDraft());
            boolean injected = false;

            boolean shouldMarkAdmin = (policyHashPh != null && !policyHashPh.isBlank());
            boolean isSelfBeingRemoved = isUnassignRole
                    && originalUser != null
                    && Objects.equals(p.getUser().getId(), originalUser.getId());

            String current = uc.ToString();

            if (shouldMarkAdmin && !isSelfBeingRemoved) {
                String updated = injectAllowHash(current, policyHashPh, true, true); // add to both auth & sign
                p.setProofDraft(updated);
                uc = new org.midgard.models.UserContext.UserContext(updated);
                injected = true;
            }

            // count normals (no exact ph present); legacy bh presence still classifies as admin for ordering
            if (!hasExactAllowHash(uc.ToString(), policyHashPh)) {
                normalCount++;
            }

            em.flush();
            userContexts.add(uc);
        }

        // Order: admins first (has *any* sha256:* in allow auth/sign), then normals
        List<org.midgard.models.UserContext.UserContext> ordered = Stream.concat(
                userContexts.stream().filter(ux -> isAllowAnySha256(ux.ToString())),
                userContexts.stream().filter(ux -> !isAllowAnySha256(ux.ToString()))
        ).toList();

        org.midgard.models.RequestExtensions.UserContextSignRequest req =
                new org.midgard.models.RequestExtensions.UserContextSignRequest("Admin:2");
        req.SetUserContexts(ordered.toArray(new org.midgard.models.UserContext.UserContext[0]));
        req.SetNumberOfUserContexts(normalCount);

        ChangeSetType changeSetType;
        if (type.equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
            changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
        } else if (type.equals(ChangeSetType.DEFAULT_ROLES)) {
            changeSetType = ChangeSetType.COMPOSITE_ROLE;
        } else {
            changeSetType = type;
        }

        String draft = Base64.getEncoder().encodeToString(req.GetDraft());
        ChangesetRequestEntity existing =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeRequestKey.getChangeRequestId(), changeSetType));
        if (existing == null) {
            ChangesetRequestEntity entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(changeRequestKey.getChangeRequestId());
            entity.setDraftRequest(draft);
            entity.setChangesetType(type);
            em.persist(entity);
        } else {
            existing.setDraftRequest(draft);
        }
        em.flush();
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception {}

    @Override
    public void handleDeleteRequest(KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception {}

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {}

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, T entity) { return null; }

    // ------------------------- Helpers -------------------------

    private void commitUserContextToDatabase(KeycloakSession session, AccessProofDetailEntity userContext, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        String accessProofSig = userContext.getSignature();
        if (accessProofSig == null || accessProofSig.isEmpty()) {
            throw new Exception("Could not find authorization signature for this user context. Request denied.");
        }

        if (userContext.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)
                || userContext.getChangesetType().equals(ChangeSetType.CLIENT)
                || userContext.getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {

            ClientEntity clientEntity = em.find(ClientEntity.class, userContext.getClientId());
            TideClientDraftEntity defaultUserContext = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", clientEntity)
                    .getSingleResult();

            defaultUserContext.setDefaultUserContext(userContext.getProofDraft());
            defaultUserContext.setDefaultUserContextSig(accessProofSig);
            em.flush();
            return;
        }

        UserClientAccessProofEntity userClientAccess =
                em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(userContext.getUser(), userContext.getClientId()));

        if (userClientAccess == null) {
            UserClientAccessProofEntity newAccess = new UserClientAccessProofEntity();
            newAccess.setUser(userContext.getUser());
            newAccess.setClientId(userContext.getClientId());
            newAccess.setAccessProof(userContext.getProofDraft());
            newAccess.setAccessProofSig(accessProofSig);
            newAccess.setIdProofSig("");
            newAccess.setAccessProofMeta("");
            em.persist(newAccess);
        } else {
            userClientAccess.setAccessProof(userContext.getProofDraft());
            userClientAccess.setAccessProofMeta("");
            userClientAccess.setAccessProofSig(accessProofSig);
            userClientAccess.setIdProofSig("");
            em.merge(userClientAccess);
        }
    }

    // inject "ph" into allow.{auth,sign} (adds if missing)
    private static String injectAllowHash(String userContextJson, String hash, boolean includeAuth, boolean includeSign) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = root.with("allow");
            if (includeAuth) appendIfMissing(allow.withArray("auth"), hash);
            if (includeSign) appendIfMissing(allow.withArray("sign"), hash);
            return om.writeValueAsString(JsonSorter.parseAndSortArrays(root.toString()));
        } catch (Exception e) {
            throw new RuntimeException("injectAllowHash failed", e);
        }
    }

    private static void appendIfMissing(ArrayNode arr, String value) {
        for (int i = 0; i < arr.size(); i++) {
            if (Objects.equals(arr.get(i).asText(), value)) return;
        }
        arr.add(value);
    }

    // classify as "admin" if allow.{auth|sign} has ANY "sha256:*"
    private static boolean isAllowAnySha256(String userContextJson) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = (ObjectNode) root.get("allow");
            if (allow == null) return false;
            return arrayHasSha256(allow.get("auth")) || arrayHasSha256(allow.get("sign"));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean hasExactAllowHash(String userContextJson, String hash) {
        if (hash == null || hash.isBlank()) return false;
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = (ObjectNode) root.get("allow");
            if (allow == null) return false;
            return arrayHasValue(allow.get("auth"), hash) || arrayHasValue(allow.get("sign"), hash);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean arrayHasSha256(com.fasterxml.jackson.databind.JsonNode arr) {
        if (arr == null || !arr.isArray()) return false;
        for (var it : arr) {
            if (it.isTextual() && it.asText().startsWith("sha256:")) return true;
        }
        return false;
    }

    private static boolean arrayHasValue(com.fasterxml.jackson.databind.JsonNode arr, String value) {
        if (arr == null || !arr.isArray()) return false;
        for (var it : arr) {
            if (it.isTextual() && Objects.equals(it.asText(), value)) return true;
        }
        return false;
    }

    /** unwrap JSON bundle { "auth": "...", "sign": "..." } to a compact; prefer "auth". */
    private static String unwrapCompactOrFirst(String stored) {
        if (stored == null) return null;
        String s = stored.trim();
        if (!s.startsWith("{")) return s;
        try {
            ObjectMapper om = new ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> m = om.readValue(s, Map.class);
            Object v = m.get("auth");
            if (v == null && !m.isEmpty()) v = m.values().iterator().next();
            return v == null ? null : String.valueOf(v);
        } catch (Exception e) {
            return s; // fallback
        }
    }

    /** ph = sha256( UTF8("header64.payload64") ), uppercase hex, with "sha256:" prefix. */
    private static String computePolicyHashFromCompact(String compact) throws Exception {
        String[] parts = compact.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Compact string must contain header.payload");
        String hp = parts[0] + "." + parts[1];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(hp.getBytes(StandardCharsets.UTF_8));
        String hex = java.util.HexFormat.of().withUpperCase().formatHex(digest);
        return "sha256:" + hex;
    }
}
