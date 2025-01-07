package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.utils.TideRolesUtil;

import java.util.Arrays;
import java.util.Objects;

import static org.keycloak.models.ImpersonationConstants.IMPERSONATION_ROLE;
import static org.tidecloak.changeset.utils.TideEntityUtils.toRoleEntity;

public class RoleUtils {

    public static Boolean commitDefaultRolesOnInitiation(KeycloakSession session, RealmModel realm, RoleModel parent, RoleModel child, EntityManager em) {
        // Wrap parent and child roles
        RoleModel parentRole = TideRolesUtil.wrapRoleModel(parent, session, realm);
        RoleEntity parentEntity = toRoleEntity(parentRole, em);
        RoleModel childRole = TideRolesUtil.wrapRoleModel(child, session, realm);
        RoleEntity childEntity = toRoleEntity(childRole, em);

        // Role names
        String parentName = parent.getName();
        String childName = child.getName();

        // Check and persist draft if required
        if (shouldPersistDraft(parentName, childName, realm)) {
            persistDraft(parentEntity, childEntity, em);
            return true;
        }

        // Additional checks without persisting
        return shouldApproveDefaultRole(parentName, childName);
    }

    private static boolean shouldPersistDraft(String parentName, String childName, RealmModel realm) {
        return (isRealmAdmin(parentName) && (isInAllRealmRoles(childName) || isCreateRealm(childName) || isImpersonation(childName))) ||
                (isManageAccount(parentName) && isManageAccountLinks(childName)) ||
                (isManageConsent(parentName) && isViewConsent(childName)) ||
                (isViewClients(parentName) && (isQueryClients(childName) || isQueryGroups(childName))) ||
                (isDefaultRole(parentName, realm) && isDefaultAccountRole(childName));
    }

    private static boolean shouldApproveDefaultRole(String parentName, String childName) {
        return (isAdminViewUsers(parentName) && (isQueryUsers(childName) || isQueryGroups(childName))) ||
                (isAdminViewClients(parentName) && isQueryClients(childName));
    }

    private static boolean isRealmAdmin(String entityName) {
        return Objects.equals(entityName, AdminRoles.REALM_ADMIN);
    }

    private static boolean isInAllRealmRoles(String childName) {
        return Arrays.asList(AdminRoles.ALL_REALM_ROLES).contains(childName);
    }

    private static boolean isCreateRealm(String childName) {
        return Objects.equals(childName, AdminRoles.CREATE_REALM);
    }

    private static boolean isManageAccount(String entityName) {
        return Objects.equals(entityName, AccountRoles.MANAGE_ACCOUNT);
    }

    private static boolean isManageAccountLinks(String childName) {
        return Objects.equals(childName, AccountRoles.MANAGE_ACCOUNT_LINKS);
    }

    private static boolean isManageConsent(String entityName) {
        return Objects.equals(entityName, AccountRoles.MANAGE_CONSENT);
    }

    private static boolean isAdminViewUsers(String entityName) {
        return Objects.equals(entityName, AdminRoles.VIEW_USERS);
    }

    private static boolean isAdminViewClients(String entityName) {
        return Objects.equals(entityName, AdminRoles.VIEW_CLIENTS);
    }

    private static boolean isQueryUsers(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_USERS);
    }

    private static boolean isViewConsent(String childName) {
        return Objects.equals(childName, AccountRoles.VIEW_CONSENT);
    }

    private static boolean isViewClients(String entityName) {
        return Objects.equals(entityName, AdminRoles.VIEW_CLIENTS);
    }

    private static boolean isQueryClients(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_CLIENTS);
    }

    private static boolean isQueryGroups(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_GROUPS);
    }

    private static boolean isImpersonation(String childName) {
        return Objects.equals(childName, IMPERSONATION_ROLE);
    }

    private static boolean isDefaultRole(String entityName, RealmModel realm) {
        return Objects.equals(entityName, realm.getDefaultRole().getName());
    }

    private static boolean isDefaultAccountRole(String childName) {
        return Arrays.asList(AccountRoles.DEFAULT).contains(childName);
    }

    private static void persistDraft(RoleEntity parentEntity, RoleEntity childEntity, EntityManager em) {
        TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setComposite(parentEntity);
        draft.setChildRole(childEntity);
        draft.setAction(ActionType.CREATE);
        draft.setDraftStatus(DraftStatus.ACTIVE);
        em.persist(draft);
        em.flush();
    }
}
