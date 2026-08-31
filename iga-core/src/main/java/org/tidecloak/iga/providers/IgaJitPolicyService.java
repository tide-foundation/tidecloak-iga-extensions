package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.midgard.Serialization.Tools;
import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the per-grant policy and request payload for a just-in-time token.
 *
 * <p>A JIT token is a {@code BasicCustom} sign model rather than a bespoke one, and that choice
 * carries the enforcement. {@code BaseCustomSignRequest} permits ONLY the Policy authorization
 * flow, and {@code PolicyAuthorizationFlow} forces {@code RequireDataValidation()} for a custom
 * request, so the contract cannot be bypassed for it. {@code BasicCustomRequest} then signs the
 * whole Draft, which is exactly the bytes the contract validated. Signing precisely what was
 * validated is what makes the output a credential rather than an assertion the caller made up.</p>
 *
 * <p>The ork does the rest: {@code PolicyAuthorizationFlow} verifies the policy signature, refuses
 * an expired policy, checks the model id and that the policy is bound to this key, and only then
 * runs the contract. Nothing here decides access.</p>
 */
public final class IgaJitPolicyService {

    /**
     * The model id a JIT policy authorizes. Custom models are matched by pattern rather than
     * registered, so this needs no counterpart on the ork.
     */
    public static final String JIT_MODEL_ID = "BasicCustom<JitToken>:BasicCustom<1>";

    /**
     * Draft layout, shared with the contract's ValidateJitToken. These are two halves of one wire
     * format: changing either alone produces a payload the contract rejects, or worse, one it reads
     * differently from how it was written.
     */
    public static final int DRAFT_SUMMARY    = 0;   // human-readable, shown to approvers
    public static final int DRAFT_SUBJECT    = 1;
    public static final int DRAFT_ASSESSMENT = 2;
    public static final int DRAFT_ROLE       = 3;
    public static final int DRAFT_EXPIRY     = 4;   // int64 little-endian epoch seconds

    /** The contract's own ceiling for MaxJitLifetimeSeconds. */
    static final int MAX_JIT_LIFETIME_SECONDS = 86400;

    /** Keycloak's default access-token lifespan, used when the realm does not set one. */
    static final int DEFAULT_ACCESS_TOKEN_LIFESPAN_SECONDS = 300;

    private IgaJitPolicyService() {
    }

    /**
     * The lifetime a JIT token may have when its policy carries no expiry of its own.
     *
     * <p>Taken from the realm's real access-token lifespan, so a standing grant mints a credential
     * that lives no longer than an ordinary token from the same realm. A realm that has not set one
     * reports 0 or less; Keycloak's own default applies then, rather than treating "unset" as
     * "unbounded".</p>
     */
    public static int jitLifetimeSeconds(RealmModel realm) {
        int lifespan = realm == null ? 0 : realm.getAccessTokenLifespan();
        if (lifespan <= 0) {
            lifespan = DEFAULT_ACCESS_TOKEN_LIFESPAN_SECONDS;
        }
        return Math.min(lifespan, MAX_JIT_LIFETIME_SECONDS);
    }

    /**
     * The policy for one grant. One policy per grant, so the role and the assessment are pinned
     * here rather than read from whatever the request happens to ask for.
     *
     * @param expiry epoch seconds, or null for a standing grant
     */
    public static Policy buildPolicy(RealmModel realm, String contractId, String vuid,
                                     String resource, String grantedRole, String assessmentId,
                                     String tier, Long expiry) {
        if (contractId == null || contractId.isBlank())   throw new IllegalArgumentException("contractId is required");
        if (vuid == null || vuid.isBlank())               throw new IllegalArgumentException("vuid is required");
        if (resource == null || resource.isBlank())       throw new IllegalArgumentException("resource is required");
        if (grantedRole == null || grantedRole.isBlank()) throw new IllegalArgumentException("grantedRole is required");

        String scope = (assessmentId == null || assessmentId.isBlank()) ? "org" : "assessment";

        // Inserted in sorted key order deliberately. Midgard's PolicyParameters is insertion
        // ordered and the ork's is sorted, so the same logical policy serialises differently
        // depending on insertion order. Sorted order is the one the ork reconstructs.
        PolicyParameters params = new PolicyParameters();
        params.put("AssessmentId", assessmentId == null ? "" : assessmentId);
        params.put("GrantedRole", grantedRole);
        params.put("MaxJitLifetimeSeconds", jitLifetimeSeconds(realm));
        params.put("Resource", resource);
        params.put("Scope", scope);
        params.put("Tier", tier == null || tier.isBlank() ? "content" : tier);

        return new Policy(contractId, new String[]{JIT_MODEL_ID}, vuid,
                ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params, expiry);
    }

    /**
     * The request payload the ork signs, and the same bytes the contract validates.
     *
     * <p>The expiry written here must equal the policy's, which is what the contract enforces: a
     * credential that outlived the grant authorizing it would defeat the point of a grant having an
     * expiry at all. Passing the policy rather than a loose number is what keeps the two from
     * drifting apart at the one place they must agree.</p>
     */
    public static byte[] buildDraft(Policy policy, String subjectVuid, String assessmentId,
                                    String grantedRole, String summary) {
        if (policy == null) throw new IllegalArgumentException("policy is required");

        Long expiry = policy.getExpiry();
        if (expiry == null) {
            throw new IllegalArgumentException(
                    "a JIT token needs an expiry; a policy without one cannot pin the credential's lifetime");
        }

        return Tools.CreateTideMemory(
                (summary == null ? "" : summary).getBytes(StandardCharsets.UTF_8),
                subjectVuid.getBytes(StandardCharsets.UTF_8),
                (assessmentId == null ? "" : assessmentId).getBytes(StandardCharsets.UTF_8),
                grantedRole.getBytes(StandardCharsets.UTF_8),
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(expiry).array());
    }

    /**
     * Whether a policy authorizes JIT tokens, so the extra rules apply only to those.
     */
    public static boolean isJitPolicy(Policy policy) {
        if (policy == null || policy.getModelIds() == null) return false;
        for (String id : policy.getModelIds()) {
            if (JIT_MODEL_ID.equals(id)) return true;
        }
        return false;
    }

    /**
     * The realm's lifespan is authoritative, whoever built the policy.
     *
     * <p>MaxJitLifetimeSeconds lives INSIDE the signed policy, so it cannot be corrected on the way
     * in; the only options are to accept it or refuse it. A policy claiming a longer fallback than
     * the realm's own tokens would let a standing grant mint a credential outliving anything the
     * realm otherwise issues, so it is refused.</p>
     *
     * @return null when acceptable, otherwise why it was refused
     */
    public static String rejectionReason(RealmModel realm, Policy policy) {
        if (!isJitPolicy(policy)) return null;

        int allowed = jitLifetimeSeconds(realm);
        Integer claimed;
        try {
            claimed = policy.GetParameter("MaxJitLifetimeSeconds", Integer.class);
        } catch (RuntimeException e) {
            return "a JIT policy must carry MaxJitLifetimeSeconds";
        }
        if (claimed == null || claimed < 1) {
            return "MaxJitLifetimeSeconds must be at least 1 second";
        }
        if (claimed > allowed) {
            return "MaxJitLifetimeSeconds " + claimed + " exceeds the realm's access token lifespan of " + allowed;
        }

        try {
            String role = policy.GetParameter("GrantedRole", String.class);
            if (role == null || role.isBlank()) {
                return "a JIT policy must pin the role it grants";
            }
        } catch (RuntimeException e) {
            return "a JIT policy must pin the role it grants";
        }
        return null;
    }
}
