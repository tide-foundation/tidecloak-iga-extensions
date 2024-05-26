package org.tidecloak.Protocol.mapper;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.models.TideClientAdapter;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
        UserModel tideUser = TideRolesUtil.wrapUserModel(userSession.getUser(), session, realm);
        Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(tideUser, session, realm, em, DraftStatus.ACTIVE, ActionType.CREATE);
        ClientModel clientModel = session.getContext().getClient();
        ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
        ClientModel wrapClientModel = new TideClientAdapter(realm, em, session, clientEntity);
        Set<RoleModel> roles = getAccess(activeRoles, wrapClientModel, clientModel.getClientScopes(true).values().stream(), wrapClientModel.isFullScopeAllowed());
        setTokenClaims(token, roles);

        Set<String> clientKeys = token.getResourceAccess().keySet();
        if (token.getAudience() != null) {
            String[] cleanAudience = Arrays.stream(token.getAudience())
                    .filter(clientKeys::contains)
                    .toArray(String[]::new);

            token.audience(cleanAudience);
        }else {
            String[] aud = Arrays.stream(clientKeys.toArray(String[]::new)).filter(x -> !Objects.equals(x, clientModel.getName())).toArray(String[]::new);
            token.audience(aud);
        }
        return token;
    }

    private void setTokenClaims(AccessToken token, Set<RoleModel> roles) {
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

        // Conditionally set realmAccess if the original token had it and it's not empty
        if (token.getRealmAccess() != null) {
            if (!realmAccess.getRoles().isEmpty()) {
                token.setRealmAccess(realmAccess);
            } else {
                token.setRealmAccess(null); // Remove realmAccess if empty
            }
        }

        // Conditionally set resourceAccess if the original token had it and it's not empty
        if (token.getResourceAccess() != null && !token.getResourceAccess().isEmpty()) {
            if (!clientAccesses.isEmpty()) {
                token.setResourceAccess(clientAccesses);
            } else {
                token.getResourceAccess().clear(); // Remove resourceAccess if empty
            }
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

    public static Set<RoleModel> getAccess(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes, boolean isFullScopeAllowed) {
        if (isFullScopeAllowed) {
            return roleModels;
        } else {

            // 1 - Client roles of this client itself
            Stream<RoleModel> scopeMappings = client.getRolesStream();

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            Stream<RoleModel> clientScopesMappings;
            clientScopesMappings = clientScopes.flatMap(ScopeContainerModel::getScopeMappingsStream);

            scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);

            // 3 - Expand scope mappings
            scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings
            roleModels.retainAll(scopeMappings.collect(Collectors.toSet()));

            return roleModels;
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
