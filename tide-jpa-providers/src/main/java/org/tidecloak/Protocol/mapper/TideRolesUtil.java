package org.tidecloak.Protocol.mapper;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.models.TideGroupAdapter;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TideRolesUtil {


    /**
     * Recursively expands composite roles into their composite.
     *
     * @param role
     * @param visited Track roles, which were already visited. Those will be ignored and won't be added to the stream. Besides that,
     *                the "visited" set itself will be updated as a result of this method call and all the tracked roles will be added to it
     * @return Stream of containing all of the composite roles and their components. Never returns {@code null}.
     */
    private static Stream<RoleModel> expandCompositeRolesStream(RoleModel role, Set<RoleModel> visited) {
        Stream.Builder<RoleModel> sb = Stream.builder();

        if (!visited.add(role)) {
            return sb.build(); // Early return if role is already visited
        }

        Deque<RoleModel> stack = new ArrayDeque<>();
        stack.push(role);

        while (!stack.isEmpty()) {
            RoleModel current = stack.pop();
            sb.add(current);

            if (current.isComposite()) {
                Stream<RoleModel> compositesStream;

                // Check if the role can be cast to CustomRoleAdapter and has the method
                if (role instanceof TideRoleAdapter) {
                    compositesStream = ((TideRoleAdapter) current).getCompositesStreamByStatus(DraftStatus.APPROVED);
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
    /**
     * @param roles
     * @return new set with composite roles expanded
     */
    public static Set<RoleModel> expandCompositeRoles(Set<RoleModel> roles) {
        Set<RoleModel> visited = new HashSet<>();

        return roles.stream()
                .flatMap(roleModel -> TideRolesUtil.expandCompositeRolesStream(roleModel, visited))
                .collect(Collectors.toSet());
    }

    /**
     * @param roles
     * @return stream with composite roles expanded
     */
    public static Stream<RoleModel> expandCompositeRolesStream(Stream<RoleModel> roles) {
        Set<RoleModel> visited = new HashSet<>();

        return roles.flatMap(roleModel -> TideRolesUtil.expandCompositeRolesStream(roleModel, visited));
    }

    /**
     * @param user
     * @return all user role mappings including all groups of user. Composite roles will be expanded
     */
    public static Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, EntityManager manager) {
        System.out.println("YOU ARE IN YOUR OWN DEEP USER ROLE MAPPINGS");
        Set<RoleModel> roleMappings;
        if (user instanceof TideUserAdapter){
            roleMappings = ((TideUserAdapter) user).getRoleMappingsStreamByStatus(DraftStatus.APPROVED).map(x-> wrapRoleModel(x, session, realm, manager)).collect(Collectors.toSet());
        }
        else{
            roleMappings = new HashSet<>();
            user.getRoleMappingsStream().collect(Collectors.toSet());
        }
        user.getGroupsStream().forEach(group -> addGroupRoles(wrapGroupModel(group, session, realm, manager), roleMappings));
        return expandCompositeRoles(roleMappings);
    }

    public static void addGroupRoles(GroupModel group, Set<RoleModel> roleMappings) {
        if(group instanceof TideGroupAdapter){
            roleMappings.addAll(((TideGroupAdapter) group).getRoleMappingsStreamByStatus(DraftStatus.APPROVED).collect(Collectors.toSet()));
        }else{
            roleMappings.addAll(group.getRoleMappingsStream().collect(Collectors.toSet()));
        }
        if (group.getParentId() == null) return;
        addGroupRoles(group.getParent(), roleMappings);
    }

    static GroupModel wrapGroupModel(GroupModel groupModel, KeycloakSession session, RealmModel realm, EntityManager em) {
        if (groupModel instanceof TideGroupAdapter) {
            return groupModel;
        }
        GroupEntity groupEntity = toGroupEntity(groupModel, em);
        return new TideGroupAdapter(realm, em, groupEntity, session);
    }
    static RoleModel wrapRoleModel(RoleModel role, KeycloakSession session, RealmModel realm, EntityManager em) {
        if (role instanceof TideRoleAdapter) {
            return role;
        }
        RoleEntity roleEntity = toRoleEntity(role, em);
        return new TideRoleAdapter(session, realm, em, roleEntity);
    }
    static UserModel wrapUserModel(UserModel userModel, KeycloakSession session, RealmModel realm, EntityManager em) {
        if (userModel instanceof TideUserAdapter) {
            return userModel;
        }
        UserEntity userEntity = toUserEntity(userModel, em);
        return new TideUserAdapter(session, realm, em, userEntity);
    }

    private static GroupEntity toGroupEntity(GroupModel model, EntityManager em) {
        if (model instanceof TideGroupAdapter) {
            return ((TideGroupAdapter) model).getEntity();
        }
        return em.getReference(GroupEntity.class, model.getId());
    }
    private static RoleEntity toRoleEntity(RoleModel model, EntityManager em) {
        if (model instanceof TideRoleAdapter) {
            return ((TideRoleAdapter) model).getEntity();
        }
        return em.getReference(RoleEntity.class, model.getId());
    }
    private static UserEntity toUserEntity(UserModel model, EntityManager em) {
        if (model instanceof TideUserAdapter) {
            return ((TideUserAdapter) model).getEntity();
        }
        return em.getReference(UserEntity.class, model.getId());
    }
}
