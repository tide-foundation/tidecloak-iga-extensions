package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.representations.AccessToken;
import org.tidecloak.UserContextUtilBase;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.models.TideRoleAdapter;
import org.tidecloak.models.TideUserAdapter;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.changeset.utils.TideEntityUtils.*;

public class UserContextUtils extends UserContextUtilBase {

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client) {
        return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                .setParameter("clientId", client.getId())
                .getResultList();
    }

    @Override
    public  Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        UserEntity userEntity = TideEntityUtils.toUserEntity(user, em);
        TideUserAdapter tideUser = TideEntityUtils.toTideUserAdapter( userEntity, session, realm);

        Set<RoleModel> roleMappings = tideUser.getRoleMappingsStreamByStatus(draftStatus).map((x) -> wrapRoleModel(x, session, realm)).collect(Collectors.toSet());

        user.getGroupsStream().forEach((group) -> {
            addGroupRoles(wrapGroupModel(group, session, realm), roleMappings, draftStatus);
        });
        Set<RoleModel> wrappedRoles = roleMappings.stream().map((r) -> (TideRoleAdapter)wrapRoleModel(r, session, realm)).collect(Collectors.toSet());
        return expandCompositeRoles(wrappedRoles, draftStatus);
    }


    @Override
    public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
        RealmModel realm = session.getContext().getRealm();

        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(TideEntityUtils.toTideRoleAdapter(roleModel, session, realm), visited, DraftStatus.ACTIVE))
                .collect(Collectors.toSet());
    }

    public static void addRoleToAccessToken(AccessToken token, RoleModel role) {
        AccessToken.Access access = null;

        if (role.getContainer() instanceof RealmModel) {
            // Handle realm-level roles
            access = token.getRealmAccess();
            if (access == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            }

            // Check for duplicates first
            if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        } else if (role.getContainer() instanceof ClientModel client) {

            // Handle client-level roles
            access = token.getResourceAccess(client.getClientId());

            if (access == null) {
                access = token.addAccess(client.getClientId());
                if (client.isSurrogateAuthRequired()) {
                    access.verifyCaller(true);
                }
            } else if (access.getRoles() != null && access.getRoles().contains(role.getName())) {
                return; // Role already exists, skip adding
            }

            // Add the role if it's not already present
            access.addRole(role.getName());
        }
    }

    public static void removeRoleFromAccessToken(AccessToken token, RoleModel role) {
        if (role.getContainer() instanceof RealmModel) {
            // Handle realm-level roles
            AccessToken.Access realmAccess = token.getRealmAccess();
            if (realmAccess != null && realmAccess.getRoles().contains(role.getName())) {
                realmAccess.getRoles().remove(role.getName());
            }
        } else if (role.getContainer() instanceof ClientModel) {
            // Handle client-level roles
            ClientModel client = (ClientModel) role.getContainer();
            AccessToken.Access clientAccess = token.getResourceAccess(client.getClientId());
            if (clientAccess != null && clientAccess.getRoles().contains(role.getName())) {
                clientAccess.getRoles().remove(role.getName());
            }
        }
    }





    private Set<RoleModel> expandCompositeRoles(Set<RoleModel> roles, DraftStatus draftStatus) {
        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> UserContextUtils.expandCompositeRolesStream(roleModel, visited, draftStatus))
                .collect(Collectors.toSet());
    }


    /**
     * Recursively expands composite roles into their composite.
     *
     * @param role
     * @param visited Track roles, which were already visited. Those will be ignored and won't be added to the stream. Besides that,
     *                the "visited" set itself will be updated as a result of this method call and all the tracked roles will be added to it
     * @return Stream of containing all of the composite roles and their components. Never returns {@code null}.
     */
    private static Stream<RoleModel> expandCompositeRolesStream(RoleModel role, Set<RoleModel> visited, DraftStatus draftStatus) {
        Stream.Builder<RoleModel> sb = Stream.builder();

        if (!visited.add(role)) {
            return sb.build(); // Early return if role is already visited
        }

        Deque<RoleModel> stack = new ArrayDeque<>();
        //TODO: if initial role is pending a delete, we do not bother expanding it.

        stack.push(role);


        while (!stack.isEmpty()) {
            RoleModel current = stack.pop();
            sb.add(current);

            if (current.isComposite()) {
                Stream<RoleModel> compositesStream;

                // Check if the role can be cast to CustomRoleAdapter and has the method
                if (role instanceof TideRoleAdapter) {
                    compositesStream = ((TideRoleAdapter) current).getCompositesStreamByStatus(draftStatus);
                } else {
                    // Fallback to default composites if not a CustomRoleAdapter
                    compositesStream = current.getCompositesStream();
                }

                compositesStream
                        .filter(r -> !visited.contains(r))
                        .forEach(r -> {
                            visited.add(r);
                            stack.push(r);
                        });
            }
        }

        return sb.build();
    }



}
