package org.tidecloak.base.iga.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSigner;
import org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSignerFactory;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.shared.models.UserContext;

import java.io.UncheckedIOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;
import static org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter.getChangeSetStatus;

public class BasicIGAUtils {

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
            RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, tideUserRoleMappingDraftEntity.getChangeRequestId());

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
            throw new BadRequestException("This method can only be run without Tide keys.");
        }
        // if approver is temp admin, check if there are users with realm-admin role. IF a realm-admin user exists, temp admin is not allowed to approve a request.
        if(isTemporaryAdmin && adminCount > 0){
            throw new BadRequestException("Temporary admin is not allowed to approve change request, contact a realm-admin to approve. User ID: " + adminUser.getId());
        }
        else if(!isTemporaryAdmin && !adminUser.hasRole(realmAdminRole)) {
            throw new BadRequestException("User is not authorized to approve requests.");
        }

        for(int i = 0; i < proofDetails.size(); i++){
            proofDetails.get(i).setSignature(adminUser.getId());
        }

        ChangesetRequestAdapter.saveAdminAuthorizaton(session, changeSet.getType().name(), changeSet.getChangeSetId(), changeSet.getActionType().name(), adminUser, "", "", "");
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

    public static String getEntityChangeRequestId(Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity) {
            return ((TideUserRoleMappingDraftEntity) entity).getChangeRequestId();
        } else if (entity instanceof TideRoleDraftEntity) {
            return ((TideRoleDraftEntity) entity).getChangeRequestId();
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
            return ((TideCompositeRoleMappingDraftEntity) entity).getChangeRequestId();
        } else if (entity instanceof TideClientDraftEntity) {
            return ((TideClientDraftEntity) entity).getChangeRequestId();
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



    public static List<AccessProofDetailEntity> getAccessProofsFromEntity(EntityManager em, Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity) {
            return getAccessProofs(em, tideUserRoleMappingDraftEntity.getChangeRequestId(), ChangeSetType.USER_ROLE);
        } else if (entity instanceof TideRoleDraftEntity tideRoleDraftEntity) {
            return getAccessProofs(em, tideRoleDraftEntity.getChangeRequestId(), ChangeSetType.ROLE);
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity tideCompositeRoleMappingDraftEntity) {
            return getAccessProofs(em, tideCompositeRoleMappingDraftEntity.getChangeRequestId(), ChangeSetType.COMPOSITE_ROLE);
        } else if (entity instanceof TideClientDraftEntity tideClientDraftEntity) {
            return getAccessProofs(em, tideClientDraftEntity.getChangeRequestId(), ChangeSetType.CLIENT_FULLSCOPE);
        }
        return null;
    }

    public static Object fetchDraftRecordEntity(EntityManager em, ChangeSetType type, String entityId) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, entityId);
            case COMPOSITE_ROLE, DEFAULT_ROLES -> em.find(TideCompositeRoleMappingDraftEntity.class, entityId);
            case ROLE -> em.find(TideRoleDraftEntity.class, entityId);
            case USER -> em.find(TideUserDraftEntity.class, entityId);
            case CLIENT_FULLSCOPE, CLIENT -> em.find(TideClientDraftEntity.class, entityId);
            default -> null;
        };
    }

    public static List<?> fetchDraftRecordEntityByRequestId(EntityManager em, ChangeSetType type, String changeSetId) {
        try {
            return switch (type) {
                case USER_ROLE -> em.createNamedQuery("GetUserRoleMappingDraftEntityByRequestId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case COMPOSITE_ROLE, DEFAULT_ROLES -> em.createNamedQuery("GetCompositeRoleMappingDraftEntityByRequestId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case ROLE -> em.createNamedQuery("GetRoleDraftEntityByRequestId", TideRoleDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case USER -> em.createNamedQuery("GetUserEntityByRequestId", TideUserDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case CLIENT, CLIENT_FULLSCOPE -> em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                default -> null;
            };
        } catch (NoResultException e) {
            return null;
        }
    }
    public static Object fetchDraftRecordEntitiesByRequestIdAndClientAndUser(EntityManager em, ChangeSetType type, String changeSetId, UserEntity user, String clientId) {
        try {
            return switch (type) {
                case USER_ROLE -> em.createNamedQuery("getUserRoleMappingsByUserAndClientIdAndRequestId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .setParameter("user", user)
                        .setParameter("clientId", clientId)
                        .getResultList();

                case COMPOSITE_ROLE, DEFAULT_ROLES -> em.createNamedQuery("GetCompositeRoleMappingDraftEntityByRequestId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case ROLE -> em.createNamedQuery("GetRoleDraftEntityByRequestId", TideRoleDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case USER -> em.createNamedQuery("GetUserEntityByRequestId", TideUserDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                case CLIENT, CLIENT_FULLSCOPE -> em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getResultList();

                default -> null;
            };
        } catch (NoResultException e) {
            return null;
        }
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


    public static void processChangeSetsForSigning(List<ChangeSetRequest> changeSets, KeycloakSession session, AdminAuth auth) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        if (changeSets == null || changeSets.isEmpty()) {
            throw new IllegalArgumentException("No change sets provided for signing.");
        }

        if (changeSets.size() > 1) {
            // Group by type and map to draft entities
            Map<ChangeSetType, List<Object>> requests =
                    changeSets.stream()
                            .collect(Collectors.groupingBy(
                                    ChangeSetRequest::getType,
                                    Collectors.flatMapping(
                                            req -> BasicIGAUtils
                                                    .fetchDraftRecordEntityByRequestId(
                                                            em, req.getType(), req.getChangeSetId()
                                                    )
                                                    .stream(),
                                            Collectors.toList()
                                    )
                            ));


            // Process grouped entities
            ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();
            ChangeSetSigner signer = ChangeSetSignerFactory.getSigner(session);
            ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);

            requests.forEach((requestType, entities) -> {
                try {
                    List<ChangesetRequestEntity> changeRequests =  processorFactory.getProcessor(requestType).combineChangeRequests(session, entities, em);

                    changeRequests.forEach(cre -> {
                        try {
                            Object draftRecordEntity = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, cre.getChangesetType(), cre.getChangesetRequestId()).get(0);
                            signer.sign(new ChangeSetRequest(cre.getChangesetRequestId(), cre.getChangesetType(), ActionType.NONE), em, session, realm, draftRecordEntity, auth);
                            committer.commit(new ChangeSetRequest(cre.getChangesetRequestId(), cre.getChangesetType(), ActionType.NONE), em, session, realm, draftRecordEntity, auth);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            });
        } else {
            // Single item path
            ChangeSetRequest changeSet = changeSets.get(0);
            Object draftRecordEntity = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId()).get(0);

            if (draftRecordEntity == null) {
                throw new Exception("Unsupported change set type for ID: " + changeSet.getChangeSetId());
            }

            ChangeSetSigner signer = ChangeSetSignerFactory.getSigner(session);
            ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);

            try {
                signer.sign(changeSet, em, session, realm, draftRecordEntity, auth);
                committer.commit(changeSet, em, session, realm, draftRecordEntity, auth);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }



}

