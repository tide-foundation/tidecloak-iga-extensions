package org.tidecloak.iga.changesetsigner.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class MultiAdmin implements Authorizer{

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));

        if (changesetRequestEntity == null){
            throw new Exception("No change-set request entity found with this recordId " + changeSet.getChangeSetId());
        }

        var config = componentModel.getConfig();

        String defaultAdminUiDomain = tideIdp.getConfig().get("changeSetEndpoint");
        String customAdminUiDomain = tideIdp.getConfig().get("CustomAdminUIDomain");
        String redirectUrlSig = tideIdp.getConfig().get("changeSetURLSig");

        URI redirectURI = new URI(defaultAdminUiDomain);
        UserSessionModel userSession = session.sessions().getUserSession(realm, auth.getToken().getSessionId());
        String port = redirectURI.getPort() == -1 ? "" : ":" + redirectURI.getPort();
        String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port + "/realms/" +
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" +userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.getToken().getSessionId(),
                redirectURI.toString(),//userSession.getNote("redirectUri"),
                redirectUrlSig,
                tideIdp.getConfig().get("homeORKurl"),
                config.getFirst("clientId"),
                config.getFirst("gVRK"),
                config.getFirst("gVRKCertificate"),
                realm.isRegistrationAllowed(),
                Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
                tideIdp.getConfig().get("LogoURL"),
                tideIdp.getConfig().get("ImageURL"),
                "approval",
                tideIdp.getConfig().get("settingsSig"),
                voucherURL, //voucherURL,
                ""
        );

        URI customDomainUri = null;
        if(customAdminUiDomain != null) {
            customDomainUri = Midgard.CreateURL(
                    auth.getToken().getSessionId(),
                    customAdminUiDomain,//userSession.getNote("redirectUri"),
                    tideIdp.getConfig().get("customAdminUIDomainSig"),
                    tideIdp.getConfig().get("homeORKurl"),
                    config.getFirst("clientId"),
                    config.getFirst("gVRK"),
                    config.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
                    tideIdp.getConfig().get("LogoURL"),
                    tideIdp.getConfig().get("ImageURL"),
                    "approval",
                    tideIdp.getConfig().get("settingsSig"),
                    voucherURL, //voucherURL,
                    ""
            );
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Opening Enclave to request approval.");
        response.put("uri", String.valueOf(uri));
        response.put("changeSetRequests", changesetRequestEntity.getDraftRequest());
        response.put("requiresApprovalPopup", "true");
        response.put("expiry", String.valueOf(changesetRequestEntity.getTimestamp() + 2628000)); // month expiry
        if(customAdminUiDomain != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }

        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }
}
