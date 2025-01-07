package org.tidecloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;

public class TideOIDCLoginProtocolFactory  extends OIDCLoginProtocolFactory {
    private static final Logger logger = Logger.getLogger(OIDCLoginProtocolFactory.class);
    public static final String ACTIVE_ROLES = "active roles";

    @Override
    public ClientScopeModel addRolesClientScope(RealmModel newRealm) {
        ProtocolMapperModel tideModel = TideRolesProtocolMapper.create(null, null, ACTIVE_ROLES, "resource_access.${client_id}.roles", true, false, true, true);
        ClientScopeModel rolesScope = KeycloakModelUtils.getClientScopeByName(newRealm, ROLES_SCOPE);
        var builtins = super.getBuiltinMappers();

        if (rolesScope == null) {
            rolesScope = newRealm.addClientScope(ROLES_SCOPE);
            rolesScope.setDescription("OpenID Connect scope for add user roles to the access token");
            rolesScope.setDisplayOnConsentScreen(true);
            rolesScope.setConsentScreenText(ROLES_SCOPE_CONSENT_TEXT);
            rolesScope.setIncludeInTokenScope(false);
            rolesScope.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            rolesScope.addProtocolMapper(builtins.get(REALM_ROLES));
            rolesScope.addProtocolMapper(builtins.get(CLIENT_ROLES));
            rolesScope.addProtocolMapper(builtins.get(AUDIENCE_RESOLVE));
            rolesScope.addProtocolMapper(tideModel);

            // 'roles' will be default client scope
            newRealm.addDefaultClientScope(rolesScope, true);
        } else {
            logger.debugf("Client scope '%s' already exists in realm '%s'. Skip creating it.", ROLES_SCOPE, newRealm.getName());
        }

        return rolesScope;
    }
}