package org.tidecloak.iga.crypto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The {@code clientSecret} blob of the realm's {@code tide-vendor-key}
 * {@code ComponentModel}, deserialized. Ported verbatim from the
 * idp-extensions key-provider {@code org.tidecloak.tidecustom.SecretKeys}
 * (the class legacy {@code IGAUtils.signInitialTideAdmin} and
 * {@code VendorResource.ConstructSignSettings} read to source the active VRK).
 *
 * <p>{@code activeVrk} is the active VRK private key the firstAdmin signing
 * ceremony signs with (via {@code Midgard.SignWithVrk}); {@code pendingVrk} /
 * {@code VZK} are carried for shape-parity with the source JSON but unused on
 * the firstAdmin sign path. {@link JsonIgnoreProperties} keeps the parse lenient
 * to any extra keys the blob may carry (e.g. a {@code history} array on newer
 * realms) so the deserialize never hard-fails on an unmodelled field.
 *
 * <p><b>These are PRIVATE KEYS — never expose in responses or logs.</b>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretKeys {
    /** The active VRK private key — what the firstAdmin ceremony signs with. */
    public String activeVrk;
    /** Pre-rotation VRK private key (unused on the firstAdmin sign path). */
    public String pendingVrk;
    /** Vendor zero key (unused on the firstAdmin sign path). */
    public String VZK;
}
