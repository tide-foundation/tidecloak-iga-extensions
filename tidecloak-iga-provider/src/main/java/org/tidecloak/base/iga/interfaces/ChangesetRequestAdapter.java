package org.tidecloak.base.iga.interfaces;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AdminAuthorizationEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ChangesetRequestAdapter {

    private static final ObjectMapper __M = new ObjectMapper();

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

        ChangesetRequestEntity envelope = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSetRequestID, ChangeSetType.valueOf(changeSetType)));
        if (envelope == null) {
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            // No Tide keys: store minimal approval & advance envelope state
            String json = "{\"id\":\"" + adminUser.getId() + "\"}";
            AdminAuthorizationEntity adminAuthorizationEntity =
                    createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), json, adminUser.getId(), em);
            envelope.addAdminAuthorization(adminAuthorizationEntity);

            BasicIGAUtils.updateEnvelopeStatus(
                    session, em, ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType));
            return;
        }

        // Delegate to Tide adapter if present
        invokeSaveAdminAuthorizaton(session, changeSetType, changeSetRequestID, changeSetActionType,
                adminUser, adminTideAuthMsg, adminTideBlindSig, adminSessionApprovalSig);
    }

    public static void saveAdminRejection(KeycloakSession session,
                                          String changeSetType,
                                          String changeSetRequestID,
                                          String changeSetActionType,
                                          UserModel adminUser) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        ChangesetRequestEntity envelope = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSetRequestID, ChangeSetType.valueOf(changeSetType)));
        if (envelope == null) {
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            // No Tide keys: store minimal rejection & advance envelope state
            AdminAuthorizationEntity adminAuthorizationEntity =
                    createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), null, adminUser.getId(), em);
            envelope.addAdminAuthorization(adminAuthorizationEntity);

            BasicIGAUtils.updateEnvelopeStatus(
                    session, em, ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType));
            return;
        }

        // Tide keys present: we still persist a rejection entry (no admin context needed)
        AdminAuthorizationEntity adminAuthorizationEntity =
                createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), null, adminUser.getId(), em);
        envelope.addAdminAuthorization(adminAuthorizationEntity);

        BasicIGAUtils.updateEnvelopeStatus(
                session, em, ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType));
    }

    public static DraftStatus getChangeSetStatus(KeycloakSession session, String changeSetId, ChangeSetType changeSetType) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        final int threshold;
        final int eligibleAdmins;

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            // Bootstrap path (no Tide keys): synthesize approver population & threshold
            RoleModel realmAdmin = session.clients()
                    .getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(AdminRoles.REALM_ADMIN);

            int active = getNumberOfActiveAdmins(session, realm, realmAdmin, em);
            eligibleAdmins = Math.max(1, active);
            threshold      = Math.max(1, (int) Math.ceil(0.7 * eligibleAdmins));
        } else {
            // Tide keys present: use TIDE_REALM_ADMIN role’s configured threshold
            RoleModel tideAdmin = session.clients()
                    .getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

            int active = getNumberOfActiveAdmins(session, realm, tideAdmin, em);
            // If literally nobody can approve yet, do NOT deny—stay in DRAFT
            if (active == 0) {
                return DraftStatus.DRAFT;
            }
            eligibleAdmins = active;
            threshold      = parseThreshold(tideAdmin);
        }

        ChangesetRequestEntity env = em.find(
                ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
        if (env == null) {
            throw new Exception("No change set request found with ID: " + changeSetId);
        }

        int approvals  = (int) env.getAdminAuthorizations().stream().filter(AdminAuthorizationEntity::getIsApproval).count();
        int rejections = (int) env.getAdminAuthorizations().stream().filter(a -> !a.getIsApproval()).count();

        // Impossible to meet threshold with remaining possible approvals => DENIED
        if ((eligibleAdmins - rejections) < threshold) {
            return DraftStatus.DENIED;
        }

        // No activity yet => DRAFT
        if (approvals == 0 && rejections == 0) {
            return DraftStatus.DRAFT;
        }

        // Reached threshold => APPROVED
        if (approvals >= threshold) {
            return DraftStatus.APPROVED;
        }

        // Otherwise => PENDING
        return DraftStatus.PENDING;
    }

    public static ChangesetRequestEntity getChangesetRequestEntity(KeycloakSession session,
                                                                   String changeSetId,
                                                                   ChangeSetType changeSetType){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
    }

    public static AdminAuthorizationEntity createAdminAuthorizationEntity(String changeSetRequestId,
                                                                          ChangeSetType changeSetType,
                                                                          String adminAuthorization,
                                                                          String userId,
                                                                          EntityManager em) throws Exception {

        ChangesetRequestEntity changesetRequestEntity = em.find(
                ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestId, changeSetType));
        if (changesetRequestEntity == null) {
            throw new Exception("No changeset request found with this id, " + changeSetRequestId);
        }

        boolean isApproval = adminAuthorization != null;
        String adminAuth = isApproval ? adminAuthorization : null;

        AdminAuthorizationEntity adminAuthorizationEntity = new AdminAuthorizationEntity();
        adminAuthorizationEntity.setId(KeycloakModelUtils.generateId());
        adminAuthorizationEntity.setChangesetRequest(changesetRequestEntity);
        adminAuthorizationEntity.setUserId(userId);
        adminAuthorizationEntity.setAdminAuthorization(adminAuth);
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
        // Count users who are members of the approving role AND have ACTIVE mapping
        return (int) session.users()
                .getRoleMembersStream(realm, tideRole)
                .filter(u -> {
                    UserEntity user = em.find(UserEntity.class, u.getId());
                    List<TideUserRoleMappingDraftEntity> entity = em.createNamedQuery(
                                    "getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                            .setParameter("user", user)
                            .setParameter("roleId", tideRole.getId())
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .getResultList();
                    return !entity.isEmpty();
                })
                .count();
    }

    /** If present, call TideChangesetRequestAdapter.saveAdminAuthorizaton(...). */
    public static void invokeSaveAdminAuthorizaton(KeycloakSession session,
                                                   String changeSetType,
                                                   String changeSetRequestID,
                                                   String changeSetActionType,
                                                   UserModel adminUser,
                                                   String adminTideAuthMsg,
                                                   String adminTideBlindSig,
                                                   String adminSessionApprovalSig) {
        try {
            Class<?> clazz = Class.forName("org.tidecloak.tide.iga.interfaces.TideChangesetRequestAdapter");
            Method m = clazz.getMethod(
                    "saveAdminAuthorizaton",
                    KeycloakSession.class,
                    String.class,
                    String.class,
                    String.class,
                    UserModel.class,
                    String.class,
                    String.class,
                    String.class
            );
            m.invoke(
                    null,
                    session,
                    changeSetType,
                    changeSetRequestID,
                    changeSetActionType,
                    adminUser,
                    adminTideAuthMsg,
                    adminTideBlindSig,
                    adminSessionApprovalSig
            );
        } catch (ClassNotFoundException e) {
            // adapter not present – silently ignore
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(
                    "org.tidecloak.tide.iga.interfaces.TideChangesetRequestAdapter is present but missing saveAdminAuthorizaton(...)", e);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(
                    "Failed to invoke saveAdminAuthorizaton on org.tidecloak.tide.iga.interfaces.TideChangesetRequestAdapter", e);
        }
    }

    public static String stageFromRep(KeycloakSession session,
                                      RealmModel realm,
                                      EntityManager em,
                                      String type,
                                      String action,
                                      Map<String, Object> rep) throws Exception {
        if (type == null || type.isBlank()) throw new BadRequestException("Missing change-set type");
        ChangeSetType cst = ChangeSetType.valueOf(type.trim().toUpperCase().replace('-', '_').replace(' ', '_'));
        ActionType act = toAction(action);
        return stageFromRep(session, realm, em, cst, act, rep);
    }

    public static String stageFromRep(KeycloakSession session,
                                      RealmModel realm,
                                      EntityManager em,
                                      ChangeSetType type,
                                      ActionType action,
                                      Map<String, Object> rep) throws Exception {
        if (type == null) throw new BadRequestException("Unknown change-set type");
        String changeSetId = null;
        if (rep != null) {
            Object v = rep.get("changeSetId");
            if (v == null) v = rep.get("id");
            if (v != null) changeSetId = String.valueOf(v).trim();
        }
        if (changeSetId == null || changeSetId.isBlank()) changeSetId = UUID.randomUUID().toString();

        ChangesetRequestEntity env = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, type));
        if (env == null) {
            env = new ChangesetRequestEntity();
            env.setChangesetRequestId(changeSetId);
            env.setChangesetType(type);
        }
        env.setDraftRequest(__M.writeValueAsString(rep == null ? Map.of() : rep));
        if (em.contains(env)) em.merge(env); else em.persist(env);
        em.flush();
        return changeSetId;
    }

    public static String stageUserRoleMappingDraft(KeycloakSession session,
                                                   RealmModel realm,
                                                   EntityManager em,
                                                   String action,
                                                   Map<String, Object> rep) throws Exception {
        return stageFromRep(session, realm, em, ChangeSetType.USER_ROLE_MAPPING, toAction(action), rep);
    }

    private static ActionType toAction(String a) {
        if (a == null) return ActionType.CREATE;
        String s = a.trim().toUpperCase();
        try { return ActionType.valueOf(s); }
        catch (IllegalArgumentException e) {
            if ("POST".equals(s)) return ActionType.CREATE;
            if ("PUT".equals(s) || "PATCH".equals(s)) return ActionType.UPDATE;
            if ("DELETE".equals(s)) return ActionType.DELETE;
            return ActionType.CREATE;
        }
    }
}
