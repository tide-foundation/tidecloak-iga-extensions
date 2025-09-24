package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.AdminAuthorizerBuilder;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.RoleAuthorizerPolicyDraftEntity;
import org.tidecloak.shared.models.SecretKeys;

import java.net.URI;
import java.util.*;
import java.util.Base64;

import static org.tidecloak.base.iga.TideRequests.RoleAuthorizerPolicyDrafts.commitRoleAuthorizerPolicy;
import static org.tidecloak.base.iga.TideRequests.RoleAuthorizerPolicyDrafts.getDraftRoleAuthorizerPolicy;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

public class MultiAdmin implements Authorizer {

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet,
                                       EntityManager em,
                                       KeycloakSession session,
                                       RealmModel realm,
                                       Object draftEntity,
                                       AdminAuth auth,
                                       AuthorizerEntity authorizer,
                                       ComponentModel componentModel) throws Exception {

        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
        if (tideIdp == null) {
            throw new BadRequestException("Tide IdP not configured for realm " + realm.getName());
        }

        ObjectMapper M = new ObjectMapper();
        ChangesetRequestEntity env = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (env == null) {
            throw new BadRequestException("No change-set request entity found: "
                    + changeSet.getChangeSetId() + " / " + changeSet.getType());
        }

        var cfg = componentModel.getConfig();
        String defaultAdminUiDomain = tideIdp.getConfig().get("changeSetEndpoint");
        String customAdminUiDomain  = tideIdp.getConfig().get("CustomAdminUIDomain");
        String redirectUrlSig       = tideIdp.getConfig().get("changeSetURLSig");

        if (defaultAdminUiDomain == null || redirectUrlSig == null) {
            throw new BadRequestException("Tide IdP settings are missing signatures/endpoint for approval flow");
        }

        URI redirectURI = new URI(defaultAdminUiDomain);
        UserSessionModel userSession =
                session.sessions().getUserSession(realm, auth.getToken().getSessionId());

        String port = redirectURI.getPort() == -1 ? "" : ":" + redirectURI.getPort();
        String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port
                + "/realms/" + realm.getName()
                + "/tidevouchers/fromUserSession?sessionId=" + userSession.getId();

        URI primaryUri = Midgard.CreateURL(
                auth.getToken().getSessionId(),
                redirectURI.toString(),
                redirectUrlSig,
                tideIdp.getConfig().get("homeORKurl"),
                cfg.getFirst("clientId"),
                cfg.getFirst("gVRK"),
                cfg.getFirst("gVRKCertificate"),
                realm.isRegistrationAllowed(),
                Boolean.parseBoolean(tideIdp.getConfig().getOrDefault("backupOn", "false")),
                tideIdp.getConfig().get("LogoURL"),
                tideIdp.getConfig().get("ImageURL"),
                "approval",
                tideIdp.getConfig().get("settingsSig"),
                voucherURL,
                ""
        );

        URI customDomainUri = null;
        if (customAdminUiDomain != null) {
            customDomainUri = Midgard.CreateURL(
                    auth.getToken().getSessionId(),
                    customAdminUiDomain,
                    tideIdp.getConfig().get("customAdminUIDomainSig"),
                    tideIdp.getConfig().get("homeORKurl"),
                    cfg.getFirst("clientId"),
                    cfg.getFirst("gVRK"),
                    cfg.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.parseBoolean(tideIdp.getConfig().getOrDefault("backupOn", "false")),
                    tideIdp.getConfig().get("LogoURL"),
                    tideIdp.getConfig().get("ImageURL"),
                    "approval",
                    tideIdp.getConfig().get("settingsSig"),
                    voucherURL,
                    ""
            );
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Opening Enclave to request approval.");
        response.put("uri", String.valueOf(primaryUri));
        response.put("changeSetRequests", env.getDraftRequest());
        response.put("requiresApprovalPopup", "true");
        response.put("expiry", String.valueOf(env.getTimestamp() + 2628000)); // +30 days
        if (customDomainUri != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }
        return Response.ok(M.writeValueAsString(response)).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet,
                                         EntityManager em,
                                         KeycloakSession session,
                                         RealmModel realm,
                                         Object draftEntity,
                                         AdminAuth auth,
                                         AuthorizerEntity authorizer,
                                         ComponentModel componentModel) throws Exception {

        ObjectMapper M = new ObjectMapper();
        ChangesetRequestEntity env = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (env == null) {
            throw new BadRequestException("No change-set request entity found: "
                    + changeSet.getChangeSetId() + " / " + changeSet.getType());
        }

        var cfg = componentModel.getConfig();

        // Gather & order user-context proofs
        List<AccessProofDetailEntity> proofs =
                BasicIGAUtils.getAccessProofs(em, BasicIGAUtils.getEntityChangeRequestId(draftEntity), changeSet.getType());
        proofs.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        List<AccessProofDetailEntity> orderedProofs = sortAccessProof(proofs);
        List<UserContext> orderedCtx = orderedProofs.stream()
                .map(p -> new UserContext(p.getProofDraft()))
                .toList();

        // Build sign request
        UserContextSignRequest req = new UserContextSignRequest("Admin:1");
        req.SetDraft(Base64.getDecoder().decode(env.getDraftRequest()));
        req.SetUserContexts(orderedCtx.toArray(new UserContext[0]));
        req.SetCustomExpiry(env.getTimestamp() + 2628000L);

        // Authorizer block
        AdminAuthorizerBuilder ab = new AdminAuthorizerBuilder();
        boolean authorityAssignment = isAuthorityAssignment(session, draftEntity, em);
        if (authorityAssignment) {
            RoleAuthorizerPolicyDraftEntity apDraft =
                    getDraftRoleAuthorizerPolicy(session, changeSet.getChangeSetId());
            if (apDraft == null) {
                throw new BadRequestException("AuthorizerPolicy draft not found for changeSet " + changeSet.getChangeSetId());
            }
            ab.AddAuthorizerPolicy(apDraft.getApCompact());
        } else {
            ClientModel realmMgmt = session.clients().getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
            if (realmMgmt == null) throw new BadRequestException("Missing realm-management client");
            RoleModel tideRole = session.roles().getClientRole(realmMgmt, org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            if (tideRole == null) throw new BadRequestException("Missing tide-realm-admin role");
            String apCompact = tideRole.getFirstAttribute("tide.ap.model");
            if (apCompact == null || apCompact.isBlank()) {
                throw new BadRequestException("Realm admin role missing tide.ap.model");
            }
            ab.AddAuthorizerPolicy(apCompact);
        }

        // Add admin approvals collected on the envelope
        env.getAdminAuthorizations()
                .forEach(a -> ab.AddAdminAuthorization(AdminAuthorization.FromString(a.getAdminAuthorization())));

        // Sign settings
        int t = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int n = Integer.parseInt(System.getenv("THRESHOLD_N"));
        if (t == 0 || n == 0) throw new RuntimeException("Env variables not set: THRESHOLD_T, THRESHOLD_N");

        SecretKeys keys = M.readValue(cfg.getFirst("clientSecret"), SecretKeys.class);

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = cfg.getFirst("vvkId");
        settings.HomeOrkUrl = cfg.getFirst("systemHomeOrk");
        settings.PayerPublicKey = cfg.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = cfg.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = keys.activeVrk;          // use active VRK to sign
        settings.Threshold_T = t;
        settings.Threshold_N = n;

        // Attach authorizer to request
        ab.AddAuthorizationToSignRequest(req);

        // Sign
        SignatureResponse resp = Midgard.SignModel(settings, req);

        // Persist signatures back to proofs (AP sig is first when authority-assignment)
        if (authorityAssignment) {
            for (int i = 0; i < orderedProofs.size(); i++) {
                orderedProofs.get(i).setSignature(resp.Signatures[i + 1]); // shift by 1
            }
            commitRoleAuthorizerPolicy(session, changeSet.getChangeSetId(), draftEntity, resp.Signatures[0]);
        } else {
            for (int i = 0; i < orderedProofs.size(); i++) {
                orderedProofs.get(i).setSignature(resp.Signatures[i]);
            }
        }

        // NOW commit the change-set into Keycloak using the new committer
        ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
        Response commitResp = committer.commit(changeSet, em, session, realm, draftEntity, auth);

        em.flush();
        return commitResp != null ? commitResp : Response.ok("Change set approved and committed").build();
    }
}
