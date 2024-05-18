package org.tidecloak.Protocol.mapper;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;

import static org.keycloak.protocol.ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER;
import static org.tidecloak.AdminRealmResource.TideAdminRealmResource.getAccess;

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
        UserModel tideUser = TideRolesUtil.wrapUserModel(userSession.getUser(), session, realm);
        Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE);
        ClientModel clientModel = session.getContext().getClient();
        Set<RoleModel> roles = getAccess(activeRoles, clientModel, clientModel.getClientScopes(true).values().stream());
        setTokenClaims(token, roles, session);

        return token;
    }

    private void setTokenClaims(AccessToken token, Set<RoleModel> roles, KeycloakSession session) {
        AccessToken.Access realmAccess = new AccessToken.Access();
        Map<String, AccessToken.Access> clientAccesses = new HashMap<>();
        for (RoleModel role : roles) {
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
        if (!token.getResourceAccess().entrySet().isEmpty()) {
            token.setResourceAccess(clientAccesses);
        }
    }
    public static ProtocolMapperModel create(String clientId, String clientRolePrefix,
                                             String name,
                                             String tokenClaimName,
                                             boolean accessToken, boolean idToken, boolean introspectionEndpoint) {
        return create(clientId, clientRolePrefix, name, tokenClaimName, accessToken, idToken, introspectionEndpoint, false);

    }

    public static ProtocolMapperModel create(String clientId, String clientRolePrefix,
                                             String name,
                                             String tokenClaimName,
                                             boolean accessToken, boolean idToken, boolean introspectionEndpoint, boolean multiValued) {
        ProtocolMapperModel mapper = OIDCAttributeMapperHelper.createClaimMapper(name, "foo",
                tokenClaimName, "String",
                accessToken, idToken, false, introspectionEndpoint,
                PROVIDER_ID);

        mapper.getConfig().put(ProtocolMapperUtils.MULTIVALUED, String.valueOf(multiValued));
        mapper.getConfig().put(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID, clientId);
        mapper.getConfig().put(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX, clientRolePrefix);
        return mapper;
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
