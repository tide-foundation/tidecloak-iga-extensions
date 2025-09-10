package org.tidecloak.tide.iga.ChangeSetProcessors;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDrafts;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDraftsForRealm;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;

public class TideChangeSetProcessor<T> implements ChangeSetProcessor<T> {

    /**
     * Updates all affected user context drafts triggered by a change request commit.
     * Rebuilds the UserContextSignRequest using Admin:2 and classifies admin contexts
     * by the presence of any sha256:* entry in userContext.allow.{auth|sign}.
     */
    @Override
    public void updateAffectedUserContexts(KeycloakSession session, RealmModel realm, ChangeSetRequest change, T entity, EntityManager em) throws Exception {
        // Group proofDetails by changeRequestId
        Map<ChangeRequestKey, List<AccessProofDetailEntity>> groupedProofDetails = getUserContextDraftsForRealm(em, realm.getId()).stream()
                .filter(proof -> !Objects.equals(proof.getChangeRequestKey().getChangeRequestId(), change.getChangeSetId()))
                .sorted(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed())
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getChangeRequestKey));

        groupedProofDetails.forEach((changeRequestKey, details) -> {
            try {
                List<UserContext> userContexts = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", changeRequestKey.getChangeRequestId())
                        .getResultStream()
                        .map(p -> new UserContext(p.getProofDraft()))
                        .collect(Collectors.toList());

                if (userContexts.isEmpty()) return;

                // Admin = any context carrying at least one sha256:* in allow.{auth|sign}
                List<UserContext> admins = userContexts.stream()
                        .filter(uc -> isAdminByAllowAny(uc.ToString()))
                        .toList();
                List<UserContext> normals = userContexts.stream()
                        .filter(uc -> !isAdminByAllowAny(uc.ToString()))
                        .toList();

                List<UserContext> orderedContext = Stream.concat(admins.stream(), normals.stream()).toList();
                int normalCount = normals.size();

                // Use Admin:2 for Forseti policy flow
                UserContextSignRequest updatedReq = new UserContextSignRequest("Admin:2");
                updatedReq.SetUserContexts(orderedContext.toArray(new UserContext[0]));
                updatedReq.SetNumberOfUserContexts(normalCount);

                ChangeSetType changeSetType;
                if (details.get(0).getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
                    changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
                } else if (details.get(0).getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
                    changeSetType = ChangeSetType.COMPOSITE_ROLE;
                } else {
                    changeSetType = details.get(0).getChangesetType();
                }

                ChangesetRequestEntity changesetRequestEntity =
                        ChangesetRequestAdapter.getChangesetRequestEntity(session, changeRequestKey.getChangeRequestId(), changeSetType);
                if (changesetRequestEntity != null) {
                    changesetRequestEntity.setDraftRequest(Base64.getEncoder().encodeToString(updatedReq.GetDraft()));
                }
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Commits a change request by finalizing the draft and applying changes to the database.
     */
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

        // Re-generate for CLIENT_FULLSCOPE that belong to this realm
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
     * Save one UserContext draft; inject Forseti Policy BH instead of InitCertHash.
     */
    @Override
    public void saveUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm, ClientModel clientModel,
                                     UserEntity user, ChangeRequestKey changeRequestKey, ChangeSetType type, String proofDraft) throws Exception {

        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, changeRequestKey.getChangeRequestId(), type);
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

        boolean isTideAdminRole;
        boolean isUnassignRole;
        UserModel originalUser;

        // NEW: AuthorizerPolicy (compact) → BH linkage
        AuthorizerPolicy ap = null;
        String bh = null;

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

            RoleInitializerCertificateDraftEntity roleInitCertDraft = getDraftRoleInitCert(session, changeRequestKey.getChangeRequestId());
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
                ap = AuthorizerPolicy.fromCompact(roleInitCertDraft.getInitCert());
            } else if (isTideAdminRole) {
                // 2) Otherwise for firstAdmin path, use the persisted AP on the TIDE_REALM_ADMIN role draft
                RoleEntity roleRef = em.getReference(RoleEntity.class, tideRole.getId());
                TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                        .setParameter("role", roleRef)
                        .getSingleResult();
                ap = AuthorizerPolicy.fromCompact(tideRoleEntity.getInitCert());
            }

            if (ap != null && ap.payload() != null) {
                bh = ap.payload().bh; // e.g. "sha256:...."
            }
        } else {
            isTideAdminRole = false;
            isUnassignRole = false;
            originalUser = null;
        }

        List<UserContext> userContexts = new ArrayList<>();
        int normalCount = 0;

        for (AccessProofDetailEntity p : proofDetails) {
            UserContext uc = new UserContext(p.getProofDraft());

            boolean shouldMarkAdmin = (ap != null && bh != null && !bh.isBlank());
            boolean isSelfBeingRemoved = isUnassignRole
                    && originalUser != null
                    && Objects.equals(p.getUser().getId(), originalUser.getId());

            if (shouldMarkAdmin && !isSelfBeingRemoved) {
                // Inject BH into allow.{auth,sign}
                String updated = injectAllowBh(uc.ToString(), bh, true, true);
                p.setProofDraft(updated);
                uc = new UserContext(updated);
            } else {
                // Count as "normal" if it doesn't already carry this BH
                if (bh == null || !hasExactBh(uc.ToString(), bh)) {
                    normalCount++;
                }
                p.setProofDraft(uc.ToString());
            }

            em.flush();
            userContexts.add(uc);
        }

        // Order: admins first (has any sha256:* in allow), then normals
        List<UserContext> ordered = Stream.concat(
                userContexts.stream().filter(uc -> isAdminByAllowAny(uc.ToString())),
                userContexts.stream().filter(uc -> !isAdminByAllowAny(uc.ToString()))
        ).toList();

        // Build the Admin:2 request (no InitCert attached)
        UserContextSignRequest req = new UserContextSignRequest("Admin:2");
        req.SetUserContexts(ordered.toArray(new UserContext[0]));
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

    // -------------------------
    // Helpers
    // -------------------------

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

    // Inject the BH into allow.{auth,sign}
    private static String injectAllowBh(String userContextJson, String bh, boolean includeAuth, boolean includeSign) {
        try {
            ObjectMapper om = new ObjectMapper();
            var root  = (com.fasterxml.jackson.databind.node.ObjectNode) om.readTree(userContextJson);
            var allow = root.with("allow");
            if (includeAuth) appendIfMissing(allow.withArray("auth"), bh);
            if (includeSign) appendIfMissing(allow.withArray("sign"), bh);
            return om.writeValueAsString(root);
        } catch (Exception e) {
            throw new RuntimeException("injectAllowBh failed", e);
        }
    }

    private static void appendIfMissing(com.fasterxml.jackson.databind.node.ArrayNode arr, String value) {
        for (int i = 0; i < arr.size(); i++) {
            if (Objects.equals(arr.get(i).asText(), value)) return;
        }
        arr.add(value);
    }

    // An "admin" context is any that already carries at least one sha256:* linkage
    private static boolean isAdminByAllowAny(String userContextJson) {
        try {
            ObjectMapper om = new ObjectMapper();
            var root = (com.fasterxml.jackson.databind.node.ObjectNode) om.readTree(userContextJson);
            var allow = (com.fasterxml.jackson.databind.node.ObjectNode) root.get("allow");
            if (allow == null) return false;
            return arrayHasSha256(allow.get("auth")) || arrayHasSha256(allow.get("sign"));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean hasExactBh(String userContextJson, String bh) {
        if (bh == null || bh.isBlank()) return false;
        try {
            ObjectMapper om = new ObjectMapper();
            var root = (com.fasterxml.jackson.databind.node.ObjectNode) om.readTree(userContextJson);
            var allow = (com.fasterxml.jackson.databind.node.ObjectNode) root.get("allow");
            if (allow == null) return false;
            return arrayHasValue(allow.get("auth"), bh) || arrayHasValue(allow.get("sign"), bh);
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
}
