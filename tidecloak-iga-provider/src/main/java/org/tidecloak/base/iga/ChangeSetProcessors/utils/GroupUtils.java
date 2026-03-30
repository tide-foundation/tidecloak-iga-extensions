package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import org.keycloak.models.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class GroupUtils {

    /**
     * Recursively collects all members of a group and all its subgroups.
     * When a role is added/removed from a parent group, all members of subgroups
     * are also affected because Keycloak's role resolution walks UP from a user's
     * group to parent groups, inheriting roles along the way.
     */
    public static List<UserModel> getAllGroupMembersRecursive(KeycloakSession session, RealmModel realm, GroupModel group) {
        List<UserModel> allMembers = new ArrayList<>(
                session.users().getGroupMembersStream(realm, group).collect(Collectors.toList())
        );

        group.getSubGroupsStream().forEach(subGroup ->
                allMembers.addAll(getAllGroupMembersRecursive(session, realm, subGroup))
        );

        return allMembers.stream().distinct().collect(Collectors.toList());
    }
}
