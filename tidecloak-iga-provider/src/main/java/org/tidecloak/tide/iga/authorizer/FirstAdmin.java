package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

public class FirstAdmin implements Authorizer {

    private static final ObjectMapper M = new ObjectMapper();
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

        // 1) Envelope / environment (for draft bytes & expiry)
        ChangesetRequestEntity env = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (env == null) {
            throw new BadRequestException("No change-set request entity found: "
                    + changeSet.getChangeSetId() + " / " + changeSet.getType());
        }

        // 2) Load proofs → newest-first → engine order (admins first)
        List<AccessProofDetailEntity> proofs =
                BasicIGAUtils.getAccessProofs(em, BasicIGAUtils.getEntityChangeRequestId(draftEntity), changeSet.getType());
        proofs.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        List<AccessProofDetailEntity> orderedProofs = sortAccessProof(proofs);

        // 3) Possibly drop approver UC if not affected by the change
        String approverUserId = auth.getUser().getId();
        try {
            boolean approverAffected = BasicIGAUtils.isUserAffectedByChange(draftEntity, approverUserId);
            if (!approverAffected) {
                orderedProofs = orderedProofs.stream()
                        .filter(p -> !safeUcSubjectEquals(p.getProofDraft(), approverUserId))
                        .collect(Collectors.toList());
            }
        } catch (Throwable ignore) {
            // helper optional: fail-open (keep all UCs)
        }

        // 4) Build UserContext[] in the SAME order and sign via Midgard using VRK authorization
        org.midgard.models.UserContext.UserContext[] ucs = new org.midgard.models.UserContext.UserContext[orderedProofs.size()];
        for (int i = 0; i < orderedProofs.size(); i++) {
            ucs[i] = new org.midgard.models.UserContext.UserContext(orderedProofs.get(i).getProofDraft());
        }

        // Correct Midgard flow (req.GetDataToAuthorize() → SignWithVrk → SignModel) via helper
        java.util.List<String> signatures = org.tidecloak.tide.iga.utils.IGAUtils.signContextsWithVrk(
                componentModel.getConfig(), ucs, authorizer, env
        );

        if (signatures.size() != orderedProofs.size()) {
            throw new IllegalStateException("Signature count mismatch: proofs=" + orderedProofs.size() + " sigs=" + signatures.size());
        }
        for (int i = 0; i < orderedProofs.size(); i++) {
            orderedProofs.get(i).setSignature(signatures.get(i));
        }

        // 5) If authority assignment, persist AP on the target role (NOT in proofs)
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

                // Mirror threshold if present
                try {
                    var ap = org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy.fromCompact(apCompact);
                    if (ap.payload() != null && ap.payload().threshold != null) {
                        roleModel.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(ap.payload().threshold));
                    }
                } catch (Throwable ignore) { /* optional */ }
            }
        }

        em.flush();

        // 6) Response (no popup for FirstAdmin)
        Map<String, String> response = new HashMap<>();
        response.put("message", "Change set signed successfully.");
        response.put("uri", "");
        response.put("changeSetRequests", "");
        response.put("requiresApprovalPopup", "false");
        response.put("expiry", String.valueOf(env.getTimestamp() + 2628000)); // parity with other flows

        // Optional legacy status hook (replay layer may manage state instead)
        BasicIGAUtils.updateDraftStatus(changeSet.getType(), changeSet.getActionType(), draftEntity);

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

        ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
        Response commitResp = committer.commit(changeSet, em, session, realm, draftEntity, auth);

        em.flush();
        authorizer.setType("firstAdmin"); // harmless hint

        return (commitResp != null)
                ? commitResp
                : Response.ok("Change set approved and committed with authorizer type: " + authorizer.getType()).build();
    }

    /* ───────────────────────── helpers ───────────────────────── */

    private static boolean safeUcSubjectEquals(String ucJson, String userId) {
        try {
            var n = M.readTree(ucJson);
            String sub = optText(n, "sub");
            if (sub == null) {
                var user = n.get("user");
                if (user != null) {
                    var ident = user.get("identity");
                    if (ident != null) {
                        sub = optText(ident, "id");
                    }
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
            return null; // optional helper not present
        } catch (Throwable t) {
            throw new RuntimeException("Error in " + fqcn + "." + method + ": " + t.getMessage(), t);
        }
    }
}
