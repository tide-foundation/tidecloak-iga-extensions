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
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
// NOTE: update this import if your ChangeSetRequest class is in a different package now.
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
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
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
            return userContext.getInitCertHash() != null;
        });
        Stream<AccessProofDetailEntity> userProofs = accessProofDetailEntities.stream().filter(x -> {
            UserContext userContext = new UserContext(x.getProofDraft());
            return userContext.getInitCertHash() == null;
        });
        return Stream.concat(adminProofs, userProofs).toList();
    }

    public static boolean isAuthorityAssignment(KeycloakSession session, Object mapping, EntityManager em){
        if (mapping instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
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
        if (changeSetType.equals(ChangeSetType.COMPOSITE_ROLE) || changeSetType.equals(ChangeSetType.DEFAULT_ROLES)) {
            changeSetTypes.add(ChangeSetType.DEFAULT_ROLES);
            changeSetTypes.add(ChangeSetType.COMPOSITE_ROLE);
        } else if (changeSetType.equals(ChangeSetType.CLIENT_FULLSCOPE) || changeSetType.equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
            changeSetTypes.add(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT);
            changeSetTypes.add(ChangeSetType.CLIENT_FULLSCOPE);
        } else {
            changeSetTypes.add(changeSetType);
        }
        return em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .setParameter("changesetTypes", changeSetTypes)
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
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (componentModel != null) {
            throw new BadRequestException("This method can only be run without Tide keys.");
        }
        if (isTemporaryAdmin && adminCount > 0){
            throw new BadRequestException("Temporary admin is not allowed to approve change request, contact a realm-admin to approve. User ID: " + adminUser.getId());
        } else if (!isTemporaryAdmin && !adminUser.hasRole(realmAdminRole)) {
            throw new BadRequestException("User is not authorized to approve requests.");
        }

        for (AccessProofDetailEntity proofDetail : proofDetails) {
            proofDetail.setSignature(adminUser.getId());
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
                if (changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                break;
            case COMPOSITE_ROLE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE) {
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
                if (changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                break;
            case COMPOSITE_ROLE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE) {
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
        int numberOfRejections = (int) changesetRequest.getAdminAuthorizations().stream().filter(a -> !a.getIsApproval()).count();

        if ((numberOfAdmins - numberOfRejections) < Integer.parseInt(tideRealmAdmin.getFirstAttribute("tideThreshold"))) {
            return DraftStatus.DENIED;
        }
        return DraftStatus.PENDING;
    }

    /** Merge update into mainNode; arrays deduped; scalars keep existing values (except "aud" union). */
    public static void mergeInPlace(ObjectNode mainNode, ObjectNode update) {
        Iterator<Map.Entry<String, JsonNode>> fields = update.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey();
            JsonNode value = entry.getValue();

            if (!mainNode.has(key)) {
                mainNode.set(key, value);
            } else {
                JsonNode existing = mainNode.get(key);
                if (existing.isObject() && value.isObject()) {
                    mergeInPlace((ObjectNode) existing, (ObjectNode) value);
                }
                else if (existing.isArray() && value.isArray()) {
                    ArrayNode array = (ArrayNode) existing;
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    array.forEach(seen::add);
                    value.forEach(seen::add);
                    array.removeAll();
                    seen.forEach(array::add);
                }
                else if (key.equalsIgnoreCase("aud")) {
                    ArrayNode merged = JsonNodeFactory.instance.arrayNode();
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    Stream.concat(asStream(existing), asStream(value)).forEach(seen::add);
                    seen.forEach(merged::add);
                    merged.add(mainNode.get("azp"));
                    mainNode.set(key, merged);
                }
            }
        }
    }

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

    public static ObjectNode parseNode(ObjectMapper objectMapper, String json) {
        try {
            return (ObjectNode) objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Sign & commit each change-set individually (no bundling/processor factory).
     */
    public static void processChangeSetsForSigning(List<ChangeSetRequest> changeSets, KeycloakSession session, AdminAuth auth) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        if (changeSets == null || changeSets.isEmpty()) {
            throw new IllegalArgumentException("No change sets provided for signing.");
        }

        ChangeSetSigner signer = ChangeSetSignerFactory.getSigner(session);
        ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);

        for (ChangeSetRequest changeSet : changeSets) {
            Object draftRecordEntity = BasicIGAUtils
                    .fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId())
                    .stream().findFirst().orElse(null);

            if (draftRecordEntity == null) {
                throw new Exception("Unsupported change set type for ID: " + changeSet.getChangeSetId());
            }

            signer.sign(changeSet, em, session, realm, draftRecordEntity, auth);
            committer.commit(changeSet, em, session, realm, draftRecordEntity, auth);
        }
    }
}
