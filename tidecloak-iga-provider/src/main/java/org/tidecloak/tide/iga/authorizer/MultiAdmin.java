package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;

import java.net.URI;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

/**
 * New-engine MultiAdmin authorizer:
 * - Uses enclave approval UI for signing session bootstrapping
 * - Signs individual UserContext payloads using Midgard.SignWithVrk(String, vrk)
 * - AP (authorizer policy) is NOT embedded in proofs; linkage lives in UC allow.{auth|sign}
 * - Approver's UC is omitted unless the approver is affected by the change
 * - On authority assignments, writes AP compact to role attr ("tide.ap.model") and mirrors threshold
 */
public class MultiAdmin implements Authorizer {

    private static final ObjectMapper M = new ObjectMapper();

    // Role attributes
    private static final String ATTR_AP_COMPACT = "tide.ap.model";
    private static final String ATTR_THRESHOLD  = "tideThreshold";

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
        if (tideIdp == null) throw new BadRequestException("Tide IdP not configured for realm " + realm.getName());

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
        if (customDomainUri != null) response.put("customDomainUri", String.valueOf(customDomainUri));
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

        ChangesetRequestEntity env = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (env == null) {
            throw new BadRequestException("No change-set request entity found: "
                    + changeSet.getChangeSetId() + " / " + changeSet.getType());
        }

        // 1) Collect proofs for THIS envelope id (new engine)
        String envelopeId = BasicIGAUtils.resolveChangeSetId(changeSet, draftEntity);
        if (envelopeId == null || envelopeId.isBlank()) {
            throw new BadRequestException("Cannot resolve changeSet/envelope id for commit");
        }
        List<AccessProofDetailEntity> proofs =
                BasicIGAUtils.getAccessProofs(em, envelopeId, changeSet.getType());
        proofs.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        List<AccessProofDetailEntity> orderedProofs = sortAccessProof(proofs);

        // 2) Build UserContexts from stored JSON; drop approver UC if they’re not affected
        List<String> ucJsons = orderedProofs.stream()
                .map(AccessProofDetailEntity::getProofDraft)
                .collect(Collectors.toList());

        String approverUserId = auth.getUser().getId();
        try {
            boolean approverAffected = BasicIGAUtils.isUserAffectedByChange(draftEntity, approverUserId);
            if (!approverAffected) {
                ucJsons = ucJsons.stream()
                        .filter(j -> !safeUcSubjectEquals(j, approverUserId))
                        .collect(Collectors.toList());
                orderedProofs = orderedProofs.stream()
                        .filter(p -> !safeUcSubjectEquals(p.getProofDraft(), approverUserId))
                        .collect(Collectors.toList());
            }
        } catch (Throwable ignore) { /* fail-open */ }

        // 3) Raw VRK signing (SignWithVrk expects a String)
        var cfg = componentModel.getConfig();
        String clientSecretBlob = cfg.getFirst("clientSecret");
        if (clientSecretBlob == null || clientSecretBlob.isBlank()) {
            throw new BadRequestException("Missing clientSecret (SecretKeys JSON) in component config");
        }
        SecretKeys keys = M.readValue(clientSecretBlob, SecretKeys.class);
        String vrk = (keys.activeVrk != null && !keys.activeVrk.isBlank())
                ? keys.activeVrk
                : keys.VZK;
        if (vrk == null || vrk.isBlank()) {
            throw new BadRequestException("No VRK available (activeVrk/VZK are empty)");
        }

        for (int i = 0; i < ucJsons.size(); i++) {
            byte[] sig = Midgard.SignWithVrk(ucJsons.get(i), vrk); // ← pass String
            String sigB64 = Base64.getEncoder().encodeToString(sig); // persist as base64
            orderedProofs.get(i).setSignature(sigB64);
        }

        // 4) On authority assignments, persist AP compact to the role (NOT into proofs)
        if (isAuthorityAssignment(session, draftEntity, em)) {
            String targetRoleId = tryHelperString(
                    "org.tidecloak.base.iga.utils.BasicIGAUtils",
                    "resolveTargetRoleIdFromDraft",
                    new Class[]{Object.class, EntityManager.class},
                    new Object[]{draftEntity, em});
            String apCompact = tryHelperString(
                    "org.tidecloak.base.iga.utils.BasicIGAUtils",
                    "resolveApCompactFromDraft",
                    new Class[]{Object.class, EntityManager.class},
                    new Object[]{draftEntity, em});

            if (targetRoleId != null && apCompact != null && !apCompact.isBlank()) {
                RoleModel roleModel = session.roles().getRoleById(realm, targetRoleId);
                if (roleModel == null) throw new BadRequestException("Target role not found for AP update");

                roleModel.setSingleAttribute(ATTR_AP_COMPACT, apCompact);
                try {
                    var ap = org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy.fromCompact(apCompact);
                    if (ap.payload() != null && ap.payload().threshold != null) {
                        roleModel.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(ap.payload().threshold));
                    }
                } catch (Throwable ignore) { /* optional */ }
            }
        }

        // 5) Commit
        ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
        Response commitResp = committer.commit(changeSet, em, session, realm, draftEntity, auth);

        em.flush();
        return (commitResp != null) ? commitResp : Response.ok("Change set approved and committed").build();
    }

    /* Helpers */

    private static boolean safeUcSubjectEquals(String ucJson, String userId) {
        try {
            var n = M.readTree(ucJson);
            String sub = optText(n, "sub");
            if (sub == null) {
                var user = n.get("user");
                if (user != null) {
                    var ident = user.get("identity");
                    if (ident != null) sub = optText(ident, "id");
                }
            }
            return userId.equals(sub);
        } catch (Exception e) {
            return false;
        }
    }

    private static String optText(com.fasterxml.jackson.databind.JsonNode n, String field) {
        var v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : null;
    }

    private static String tryHelperString(String fqcn, String method, Class<?>[] sig, Object[] args) {
        try {
            Class<?> cls = Class.forName(fqcn);
            var m = cls.getMethod(method, sig);
            Object out = m.invoke(null, args);
            if (out == null) return null;
            String s = String.valueOf(out);
            return s.isBlank() ? null : s;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            return null;
        } catch (Throwable t) {
            throw new RuntimeException("Error in " + fqcn + "." + method + ": " + t.getMessage(), t);
        }
    }
}
