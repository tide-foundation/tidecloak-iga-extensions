package org.tidecloak.AdminRealmResource;

import org.keycloak.exportimport.ExportOptions;
import org.keycloak.exportimport.util.ExportUtils;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.UserConsentRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.models.TideUserAdapter;

import java.util.*;
import java.util.stream.Collectors;

public class TideExportUtils {

    public static UserRepresentation exportUser(KeycloakSession session, RealmModel realm, UserModel user, ExportOptions options, DraftStatus draftStatus, ActionType actionType) {
        UserRepresentation userRep = ModelToRepresentation.toRepresentation(session, realm, user);

        // Social links
        List<FederatedIdentityRepresentation> socialLinkReps = session.users().getFederatedIdentitiesStream(realm, user)
                .map(ExportUtils::exportSocialLink).collect(Collectors.toList());
        if (socialLinkReps.size() > 0) {
            userRep.setFederatedIdentities(socialLinkReps);
        }

        // Role mappings
        if (options.isGroupsAndRolesIncluded()) {
            Set<RoleModel> roles = ((TideUserAdapter) user).getRoleMappingsStreamByStatusAndAction(draftStatus,actionType).collect(Collectors.toSet());
            List<String> realmRoleNames = new ArrayList<>();
            Map<String, List<String>> clientRoleNames = new HashMap<>();
            for (RoleModel role : roles) {
                if (role.getContainer() instanceof RealmModel) {
                    realmRoleNames.add(role.getName());
                } else {
                    ClientModel client = (ClientModel)role.getContainer();
                    String clientId = client.getClientId();
                    List<String> currentClientRoles = clientRoleNames.get(clientId);
                    if (currentClientRoles == null) {
                        currentClientRoles = new ArrayList<>();
                        clientRoleNames.put(clientId, currentClientRoles);
                    }

                    currentClientRoles.add(role.getName());
                }
            }

            if (realmRoleNames.size() > 0) {
                userRep.setRealmRoles(realmRoleNames);
            }
            if (clientRoleNames.size() > 0) {
                userRep.setClientRoles(clientRoleNames);
            }
        }


        userRep.setFederationLink(user.getFederationLink());

        // Grants
        List<UserConsentRepresentation> consentReps = session.users().getConsentsStream(realm, user.getId())
                .map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
        if (consentReps.size() > 0) {
            userRep.setClientConsents(consentReps);
        }

        // Not Before
        int notBefore = session.users().getNotBeforeOfUser(realm, user);
        userRep.setNotBefore(notBefore);


        if (options.isGroupsAndRolesIncluded()) {
            List<String> groups = user.getGroupsStream().map(ModelToRepresentation::buildGroupPath).collect(Collectors.toList());
            userRep.setGroups(groups);
        }
        return userRep;
    }
}
