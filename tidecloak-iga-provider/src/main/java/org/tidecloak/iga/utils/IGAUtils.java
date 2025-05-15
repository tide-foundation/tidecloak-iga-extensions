package org.tidecloak.iga.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;

import java.io.UncheckedIOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static io.vertx.core.json.impl.JsonUtil.asStream;
import static org.tidecloak.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;
import static org.tidecloak.iga.interfaces.ChangesetRequestAdapter.getChangeSetStatus;

public class IGAUtils {

    public static List<AccessProofDetailEntity> sortAccessProof (List<AccessProofDetailEntity> accessProofDetailEntities) {
        Stream<AccessProofDetailEntity> adminProofs = accessProofDetailEntities.stream().filter(x -> {
            UserContext userContext = new UserContext(x.getProofDraft());
            if(userContext.getInitCertHash() != null) {
                return true;
            }
            return false;

        });
        Stream<AccessProofDetailEntity> userProofs = accessProofDetailEntities.stream().filter(x -> {
            UserContext userContext = new UserContext(x.getProofDraft());
            if(userContext.getInitCertHash() == null) {
                return true;
            }
            return false;

        });
        return Stream.concat(adminProofs, userProofs).toList();
    }

    public static boolean isAuthorityAssignment(KeycloakSession session, Object mapping, EntityManager em){
        if ( mapping instanceof  TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
            RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, tideUserRoleMappingDraftEntity.getId());

            return roleInitCert != null;
        }
        return false;
    }

    public static boolean isIGAEnabled(RealmModel realm) {
        String isIGAEnabled = realm.getAttribute("isIGAEnabled");
        return isIGAEnabled != null && !isIGAEnabled.isEmpty() && isIGAEnabled.equalsIgnoreCase("true");
    }

    public static List<AccessProofDetailEntity> getAccessProofs(EntityManager em, String recordId, ChangeSetType changeSetType) {
        List<ChangeSetType> changeSetTypes = new ArrayList<>();
        if(changeSetType.equals(ChangeSetType.COMPOSITE_ROLE) || changeSetType.equals(ChangeSetType.DEFAULT_ROLES) ) {
            changeSetTypes.add(ChangeSetType.DEFAULT_ROLES);
            changeSetTypes.add(ChangeSetType.COMPOSITE_ROLE);
        }
        else if (changeSetType.equals(ChangeSetType.CLIENT_FULLSCOPE) || changeSetType.equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
            changeSetTypes.add(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT);
            changeSetTypes.add(ChangeSetType.CLIENT_FULLSCOPE);
        }
        else {
            changeSetTypes.add(changeSetType);
        }
        return em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .setParameter("changesetTypes", changeSetTypes) // Pass list instead of single value
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static void approveChangeRequest(KeycloakSession session, UserModel adminUser, List<AccessProofDetailEntity> proofDetails, EntityManager em, ChangeSetRequest changeSet) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ClientModel realmManagement = session.clients().getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel realmAdminRole = session.roles().getClientRole(realmManagement, AdminRoles.REALM_ADMIN);
        int adminCount = ChangesetRequestAdapter.getNumberOfActiveAdmins(session, realm, realmAdminRole, em);
        boolean isTemporaryAdmin = adminUser.getFirstAttribute("is_temporary_admin") != null && adminUser.getFirstAttribute("is_temporary_admin").equalsIgnoreCase("true");
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel != null) {
            throw new Exception("This method can only be run without Tide keys.");
        }
        // if approver is temp admin, check if there are users with realm-admin role. IF a realm-admin user exists, temp admin is not allowed to approve a request.
        if(isTemporaryAdmin && adminCount > 0){
            throw new Exception("Temporary admin is not allowed to approve change request, contact a realm-admin to approve. User ID: " + adminUser.getId());
        }
        else if(!isTemporaryAdmin && !adminUser.hasRole(realmAdminRole)) {
            throw new Exception("User is not authorized to approve requests.");
        }

        for(int i = 0; i < proofDetails.size(); i++){
            proofDetails.get(i).setSignature(adminUser.getId());
        }

        ChangesetRequestAdapter.saveAdminAuthorizaton(session, changeSet.getType().name(), changeSet.getChangeSetId(), changeSet.getActionType().name(), adminUser, "", "", "");
    }

    public static List<String>  signInitialTideAdmin(MultivaluedHashMap<String, String> keyProviderConfig,
                                                      UserContext[] userContexts,
                                                      InitializerCertifcate initCert,
                                                      AuthorizerEntity authorizer,
                                                      ChangesetRequestEntity changesetRequestEntity ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        UserContextSignRequest req = new UserContextSignRequest("VRK:1");

        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetInitializationCertificate(initCert);
        req.SetUserContexts(userContexts);
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        // UserContext length plus initCert
        for ( int i = 0; i < userContexts.length + 1; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }

    public static List<String>  signContextsWithVrk(MultivaluedHashMap<String, String> keyProviderConfig,
                                                     UserContext[] userContexts,
                                                     AuthorizerEntity authorizer,
                                                     ChangesetRequestEntity changesetRequestEntity ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        UserContextSignRequest req = new UserContextSignRequest("VRK:1");

        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(userContexts);
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i < userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }

    public static String getEntityId(Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity) {
            return ((TideUserRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideRoleDraftEntity) {
            return ((TideRoleDraftEntity) entity).getId();
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
            return ((TideCompositeRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideClientDraftEntity) {
            return ((TideClientDraftEntity) entity).getId();
        }
        return null;
    }

    public static String getRoleIdFromEntity(Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity) {
            return tideUserRoleMappingDraftEntity.getRoleId();
        } else if (entity instanceof TideRoleDraftEntity tideRoleDraftEntity) {
            return tideRoleDraftEntity.getRole().getId();
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity tideCompositeRoleMappingDraftEntity) {
            return tideCompositeRoleMappingDraftEntity.getComposite().getId();
        }
        return null;
    }



    public static Object fetchDraftRecordEntity(EntityManager em, ChangeSetType type, String changeSetId) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, changeSetId);
            case COMPOSITE_ROLE, DEFAULT_ROLES -> em.find(TideCompositeRoleMappingDraftEntity.class, changeSetId);
            case ROLE -> em.find(TideRoleDraftEntity.class, changeSetId);
            case USER -> em.find(TideUserDraftEntity.class, changeSetId);
            case CLIENT_FULLSCOPE, CLIENT -> em.find(TideClientDraftEntity.class, changeSetId);
            default -> null;
        };
    }

    public static void updateDraftStatus(ChangeSetType changeSetType, ActionType changeSetAction, Object draftRecordEntity) {
        switch (changeSetType) {
            case USER_ROLE:
                if(changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                break;
            case COMPOSITE_ROLE:
                if(changeSetAction == ActionType.CREATE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                }
                break;
            case CLIENT_FULLSCOPE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeEnabled(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeDisabled(DraftStatus.APPROVED);
                }
                break;
            case CLIENT:
                ((TideClientDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                break;
        }
    }

    public static void updateDraftStatus(KeycloakSession session, ChangeSetType changeSetType, String changeSetID, ActionType changeSetAction, Object draftRecordEntity) throws Exception {
        DraftStatus draftStatus = getChangeSetStatus(session, changeSetID, changeSetType);

        switch (changeSetType) {
            case USER_ROLE:
                if(changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                break;
            case COMPOSITE_ROLE:
                if(changeSetAction == ActionType.CREATE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                }
                break;
            case CLIENT_FULLSCOPE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeEnabled(draftStatus);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeDisabled(draftStatus);
                }
                break;
            case CLIENT:
                ((TideClientDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                break;
        }
    }

    public static DraftStatus processDraftRejections(KeycloakSession session, ChangeSetType changeSetType, ActionType changeSetAction, Object draftRecordEntity, ChangesetRequestEntity changesetRequest) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRealmAdmin = client.getRole(Constants.TIDE_REALM_ADMIN);

        int numberOfAdmins = session.users().getRoleMembersStream(realm, tideRealmAdmin).collect(Collectors.toSet()).size();
        int numberOfRejections = changesetRequest.getAdminAuthorizations().stream().filter(a -> !a.getIsApproval()).collect(Collectors.toSet()).size();

        // Check the count of the remaining admins left to approve. If less than the threshold then just cancel change request
        if((numberOfAdmins - numberOfRejections) < Integer.parseInt(tideRealmAdmin.getFirstAttribute("tideThreshold"))) {
            return DraftStatus.DENIED;
        }
        return DraftStatus.PENDING;
    }

    /**
     * Merge update into mainNode directly, no deep clone.
     * - Objects recurse
     * - Arrays merge via HashSet (preserves order, no duplicates)
     * - Scalars: preserve mainNode’s value
     */
    public static void mergeInPlace(ObjectNode mainNode, ObjectNode update) {
        Iterator<Map.Entry<String, JsonNode>> fields = update.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey();
            JsonNode value = entry.getValue();

            if (!mainNode.has(key)) {
                // brand-new field → just add
                mainNode.set(key, value);
            }
            else {
                JsonNode existing = mainNode.get(key);
                // both are objects → recurse
                if (existing.isObject() && value.isObject()) {
                    mergeInPlace((ObjectNode) existing, (ObjectNode) value);
                }
                // both are arrays → dedupe in O(n)
                else if (existing.isArray() && value.isArray()) {
                    ArrayNode array = (ArrayNode) existing;
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    array.forEach(seen::add);
                    value.forEach(seen::add);
                    array.removeAll();  // clear existing
                    seen.forEach(array::add);
                }
                else if(key.equalsIgnoreCase("aud")){

                    // scalar/array mismatch or two scalars → unify into array
                    ArrayNode merged = JsonNodeFactory.instance.arrayNode();
                    // helper: stream either the one node or all elements if it's an array
                    Stream<JsonNode> fromExisting = asStream(existing);
                    Stream<JsonNode> fromUpdate   = asStream(value);

                    // LinkedHashSet preserves order and dedups by JsonNode.equals()
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    Stream.concat(fromExisting, fromUpdate)
                            .forEach(seen::add);

                    seen.forEach(merged::add);
                    merged.add(mainNode.get("azp"));
                    mainNode.set(key, merged);
                }
                // scalar or type mismatch → skip (keep mainNode)
            }
        }
    }

    /** If node is an ArrayNode, stream its elements; otherwise stream just the node itself. */
    private static Stream<JsonNode> asStream(JsonNode node) {
        if (node.isArray()) {
            return StreamSupport.stream(node.spliterator(), false);
        } else {
            return Stream.of(node);
        }
    }

    public static class UserRecordKey {
        public final String draftId;
        public final String username;
        public final String clientId;

        public UserRecordKey(String draftId, String username, String clientId) {
            this.draftId = draftId;
            this.username = username;
            this.clientId = clientId;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof UserRecordKey)) return false;
            UserRecordKey k = (UserRecordKey)o;
            return draftId.equals(k.draftId)
                    && username.equals(k.username)
                    && clientId.equals(k.clientId);
        }
        @Override public int hashCode() {
            return Objects.hash(draftId, username, clientId);
        }
    }

    // helper to parse a JSON string into an ObjectNode
    public static ObjectNode parseNode(ObjectMapper objectMapper, String json) {
        try {
            return (ObjectNode) objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static class UserClientKey {
        public final String userId;
        public final String clientId;
        public UserClientKey(String userId, String clientId) {
            this.userId   = userId;
            this.clientId = clientId;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof UserClientKey)) return false;
            UserClientKey k = (UserClientKey)o;
            return userId.equals(k.userId) && clientId.equals(k.clientId);
        }
        @Override public int hashCode() {
            return Objects.hash(userId, clientId);
        }
        @Override public String toString() {
            return "(" + userId + "," + clientId + ")";
        }
    }
}

