package org.tidecloak.changeset.jose.jws;

import org.keycloak.jose.jws.DefaultTokenManager;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.TokenManager;

import org.jboss.logging.Logger;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.representations.AccessToken;
import org.tidecloak.changeset.utils.UserContextUtils;
import org.tidecloak.enums.ActionType;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

public class IGATokenManager extends DefaultTokenManager {

    private static final Logger logger = Logger.getLogger(IGATokenManager.class);

    public IGATokenManager(KeycloakSession session) {
        super(session);
    }

    public AccessToken transformUserContext(KeycloakSession session, AccessToken token,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx, ActionType actionType, Set<RoleModel> rolesToAddOrRemove) {
        return ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx, mapper -> mapper.getValue() instanceof OIDCAccessTokenMapper)
                .collect(new TokenCollector<AccessToken>(token) {
                    @Override
                    protected AccessToken applyMapper(AccessToken token, Map.Entry<ProtocolMapperModel, ProtocolMapper> mapper) {
                        return ((OIDCAccessTokenMapper) mapper.getValue()).transformAccessToken(token, mapper.getKey(), session, userSession, clientSessionCtx, actionType, rolesToAddOrRemove);
                    }
                });
    }





    private abstract static class TokenCollector<T> implements Collector<Map.Entry<ProtocolMapperModel, ProtocolMapper>, TokenCollector<T>, T> {

        private T token;

        public TokenCollector(T token) {
            this.token = token;
        }

        @Override
        public Supplier<TokenCollector<T>> supplier() {
            return () -> this;
        }

        @Override
        public Function<TokenCollector<T>, T> finisher() {
            return idTokenWrapper -> idTokenWrapper.token;
        }

        @Override
        public Set<Collector.Characteristics> characteristics() {
            return Collections.emptySet();
        }

        @Override
        public BinaryOperator<TokenCollector<T>> combiner() {
            return (tMutableWrapper, tMutableWrapper2) -> { throw new IllegalStateException("can't combine"); };
        }

        @Override
        public BiConsumer<TokenCollector<T>, Map.Entry<ProtocolMapperModel, ProtocolMapper>> accumulator() {
            return (idToken, mapper) -> idToken.token = applyMapper(idToken.token, mapper);
        }

        protected abstract T applyMapper(T token, Map.Entry<ProtocolMapperModel, ProtocolMapper> mapper);

    }


}
