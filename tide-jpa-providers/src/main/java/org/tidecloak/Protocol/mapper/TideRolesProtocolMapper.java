package org.tidecloak.Protocol.mapper;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.*;

import static org.keycloak.protocol.ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER;

public class TideRolesProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "tide-roles-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, TideRolesProtocolMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        RealmModel realm = session.getContext().getRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserModel tideUser = TideRolesUtil.wrapUserModel(userSession.getUser(), session, realm, em);
        Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em);
        setTokenClaims(token, activeRoles, session);

        return token;
    }

    private void setTokenClaims(AccessToken token, Set<RoleModel> roles, KeycloakSession session) {
        AccessToken.Access realmAccess = new AccessToken.Access();
        Map<String, AccessToken.Access> clientAccesses = new HashMap<>();
        System.out.println(token);
        for (RoleModel role : roles) {
            System.out.println(role.getContainer() instanceof RealmModel);
            if (role.getContainer() instanceof RealmModel) {
                realmAccess.addRole(role.getName());
            } else if (role.getContainer() instanceof ClientModel client) {
                clientAccesses.computeIfAbsent(client.getClientId(), k -> new AccessToken.Access())
                        .addRole(role.getName());
            }
        }
        // If original token does not include any roles we dont add.
        if (token.getRealmAccess() != null) {
            token.setRealmAccess(realmAccess);
        }
        if (!token.getResourceAccess().values().isEmpty()) {
            token.setResourceAccess(clientAccesses);
        }
    }


    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Tide role mapper";
    }

    @Override
    public String getHelpText() {
        return "Retrieves approved roles only";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public int getPriority() {
        return PRIORITY_SCRIPT_MAPPER; // run last
    }
}
