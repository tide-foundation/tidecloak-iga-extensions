package org.tidecloak.base.iga.interfaces;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AdminAuthorizationEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class ChangesetRequestAdapter {

    private static final ObjectMapper M = new ObjectMapper();

    // ─────────────────────────────────────────────────────────────────────
    // NEW: Replay staging entry points
    // Called by IGAReplay endpoint (directly or via BasicIGAUtils.stageFromRep)
    // Stores the raw "rep" JSON as the draft payload; returns changeSetId.
    // ─────────────────────────────────────────────────────────────────────

    public static String stageFromRep(KeycloakSession session,
                                      RealmModel realm,
                                      EntityManager em,
                                      String type,
                                      String action,
                                      Map<String, Object> rep) throws Exception {
        ChangeSetType cst = parseType(type);
        ActionType act    = parseAction(action);
        if (cst == null) {
            throw new BadRequestException("Unsupported change-set type: " + type);
        }
        if (act == null) {
            throw new BadRequestException("Unsupported action: " + action);
        }
        return stageFromRep(session, realm, em, cst, act, rep);
    }

    public static String stageFromRep(KeycloakSession session,
                                      RealmModel realm,
                                      EntityManager em,
                                      ChangeSetType type,
                                      ActionType action,
                                      Map<String, Object> rep) throws Exception {
        if (rep == null) rep = Map.of();

        // Create an ID for this request; callers may roll their own and pass it in via rep if desired
        String changeSetId = (String) rep.getOrDefault("changeSetId", KeycloakModelUtils.generateId());

        // Upsert the envelope row keyed by (changeSetId, type)
        ChangesetRequestEntity.Key key = new ChangesetRequestEntity.Key(changeSetId, type);
        ChangesetRequestEntity existing = em.find(ChangesetRequestEntity.class, key);

        ChangesetRequestEntity cre = (existing != null) ? existing : new ChangesetRequestEntity();
        if (existing == null) {
            cre.setChangesetRequestId(changeSetId);
            cre.setChangesetType(type);
            // initialize timestamp if the entity has it (not shown here)
        }

        // Stash the raw rep JSON; committers will read & apply it
        ObjectNode body = M.createObjectNode();
        body.put("action", action.name());
        body.set("rep", M.valueToTree(rep));
        cre.setDraftRequest(body.toString());

        // Persist / flush
        if (existing == null) em.persist(cre);
        em.flush();

        return changeSetId;
    }

    private static ChangeSetType parseType(String t) {
        if (t == null) return null;
        String norm = t.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        try {
            return ChangeSetType.valueOf(norm);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static ActionType parseAction(String a) {
        if (a == null) return null;
        String s = a.trim().toUpperCase(Locale.ROOT);
        try {
            return ActionType.valueOf(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Approvals / rejections & draft status computation (kept, simplified)
    // ─────────────────────────────────────────────────────────────────────

    public static void saveAdminAuthorizaton(KeycloakSession session,
                                             String changeSetType,
                                             String changeSetRequestID,
                                             String changeSetActionType,
                                             UserModel adminUser,
                                             String adminTideAuthMsg,
                                             String adminTideBlindSig,
                                             String adminSessionApprovalSig) throws Exception {

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        ChangeSetType type = ChangeSetType.valueOf(changeSetType);
        ChangesetRequestEntity changesetRequestEntity =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestID, type));
        if (changesetRequestEntity == null) {
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }

        // If IGA (no Tide keys) — simple approval trail & draft status update
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            String json = "{\"id\":\"" + adminUser.getId() + "\"}";
            AdminAuthorizationEntity adminAuthorizationEntity =
                    createAdminAuthorizationEntity(changeSetRequestID, type, json, adminUser.getId(), em);
            changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

            List<?> drafts = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSetRequestID);
            drafts.forEach(d -> {
                try {
                    BasicIGAUtils.updateDraftStatus(session, type, changeSetRequestID, ActionType.valueOf(changeSetActionType), d);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            return;
        }

        // Tide-key path (still store an approval record so the UI reflects it);
        // If you later want to enforce special crypto here, you can serialize the msg/sigs into the JSON:
        String json = M.createObjectNode()
                .put("id", adminUser.getId())
                .put("tideAuthMsg", Objects.toString(adminTideAuthMsg, ""))
                .put("tideBlindSig", Objects.toString(adminTideBlindSig, ""))
                .put("sessionApprovalSig", Objects.toString(adminSessionApprovalSig, ""))
                .toString();

        AdminAuthorizationEntity adminAuthorizationEntity =
                createAdminAuthorizationEntity(changeSetRequestID, type, json, adminUser.getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        List<?> drafts = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSetRequestID);
        drafts.forEach(d -> {
            try {
                BasicIGAUtils.updateDraftStatus(session, type, changeSetRequestID, ActionType.valueOf(changeSetActionType), d);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public static void saveAdminRejection(KeycloakSession session,
                                          String changeSetType,
                                          String changeSetRequestID,
                                          String changeSetActionType,
                                          UserModel adminUser) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        ChangeSetType type = ChangeSetType.valueOf(changeSetType);
        ChangesetRequestEntity changesetRequestEntity =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestID, type));
        if (changesetRequestEntity == null) {
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }

        AdminAuthorizationEntity adminAuthorizationEntity =
                createAdminAuthorizationEntity(changeSetRequestID, type, null, adminUser.getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        List<?> drafts = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSetRequestID);
        drafts.forEach(d -> {
            try {
                BasicIGAUtils.updateDraftStatus(session, type, changeSetRequestID, ActionType.valueOf(changeSetActionType), d);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public static DraftStatus getChangeSetStatus(KeycloakSession session,
                                                 String changeSetId,
                                                 ChangeSetType changeSetType) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        int threshold;
        int numberOfAdmins;

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            RoleModel adminRole = session.clients()
                    .getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(AdminRoles.REALM_ADMIN);
            int numberOfActiveRealmAdmins = getNumberOfActiveAdmins(session, realm, adminRole, em);
            numberOfAdmins = Math.max(1, numberOfActiveRealmAdmins);
            threshold = Math.max(1, (int) (0.7 * numberOfAdmins));
        } else {
            RoleModel tideAdmin = session.clients()
                    .getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            threshold = parseThreshold(tideAdmin);
            numberOfAdmins = getNumberOfActiveAdmins(session, realm, tideAdmin, em);
        }

        ChangesetRequestEntity changesetRequestEntity =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
        if (changesetRequestEntity == null) {
            throw new Exception("No change set request found with ID: " + changeSetId);
        }

        int numberOfRejections = (int) changesetRequestEntity.getAdminAuthorizations()
                .stream().filter(a -> !a.getIsApproval()).count();

        if ((numberOfAdmins - numberOfRejections) < threshold) {
            return DraftStatus.DENIED;
        }

        int numberOfApprovals = (int) changesetRequestEntity.getAdminAuthorizations()
                .stream().filter(AdminAuthorizationEntity::getIsApproval).count();

        if (numberOfApprovals < 1 && numberOfRejections < 1) {
            return DraftStatus.DRAFT;
        } else if (numberOfApprovals >= threshold) {
            return DraftStatus.APPROVED;
        } else if ((numberOfAdmins - numberOfRejections) < threshold) {
            return DraftStatus.DENIED;
        } else {
            return DraftStatus.PENDING;
        }
    }

    public static ChangesetRequestEntity getChangesetRequestEntity(KeycloakSession session,
                                                                   String changeSetId,
                                                                   ChangeSetType changeSetType) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
    }

    public static AdminAuthorizationEntity createAdminAuthorizationEntity(String changeSetRequestId,
                                                                          ChangeSetType changeSetType,
                                                                          String adminAuthorizationJsonOrNull,
                                                                          String userId,
                                                                          EntityManager em) throws Exception {
        ChangesetRequestEntity changesetRequestEntity =
                em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestId, changeSetType));
        if (changesetRequestEntity == null) {
            throw new Exception("No changeset request found with this id, " + changeSetRequestId);
        }

        boolean isApproval = adminAuthorizationJsonOrNull != null;

        AdminAuthorizationEntity adminAuthorizationEntity = new AdminAuthorizationEntity();
        adminAuthorizationEntity.setId(KeycloakModelUtils.generateId());
        adminAuthorizationEntity.setChangesetRequest(changesetRequestEntity);
        adminAuthorizationEntity.setUserId(userId);
        adminAuthorizationEntity.setAdminAuthorization(adminAuthorizationJsonOrNull);
        adminAuthorizationEntity.setIsApproval(isApproval);

        em.persist(adminAuthorizationEntity);
        em.flush();
        return adminAuthorizationEntity;
    }

    private static int parseThreshold(RoleModel tideRole) throws Exception {
        String thresholdAttr = tideRole.getFirstAttribute("tideThreshold");
        if (thresholdAttr == null || thresholdAttr.isEmpty()) {
            throw new Exception("Missing or invalid 'tideThreshold' attribute for role: " + tideRole.getName());
        }
        try {
            return Integer.parseInt(thresholdAttr);
        } catch (NumberFormatException e) {
            throw new Exception("Invalid 'tideThreshold' attribute value: " + thresholdAttr, e);
        }
    }

    public static int getNumberOfActiveAdmins(KeycloakSession session,
                                              RealmModel realm,
                                              RoleModel tideRole,
                                              EntityManager em) {
        return (int) session.users()
                .getRoleMembersStream(realm, tideRole)
                .filter(u -> {
                    UserEntity user = em.find(UserEntity.class, u.getId());
                    List<TideUserRoleMappingDraftEntity> entity = em.createNamedQuery(
                                    "getUserRoleAssignmentDraftEntityByStatus",
                                    TideUserRoleMappingDraftEntity.class)
                            .setParameter("user", user)
                            .setParameter("roleId", tideRole.getId())
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .getResultList();
                    return !entity.isEmpty();
                })
                .count();
    }
}
