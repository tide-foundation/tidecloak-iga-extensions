package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoRemovalResult;

/**
 * Keycloak SPI provider exposing the {@code tide-claims} scope auto-provisioning
 * enqueue so out-of-module callers (notably {@code tidecloak-idp-extensions}'
 * server-start hook) can drive it WITHOUT a Maven dependency on {@code iga-core}.
 *
 * <p>Resolve and call it as:
 * <pre>{@code
 * TideUhoEnqueueResult r = session
 *     .getProvider(IgaSystemProvisionerProvider.class)
 *     .enqueueTideClaimsScopeProvisioning(realm, scopeRep, "system");
 * }</pre>
 *
 * <p>The default factory id is {@code "default"} (single registered
 * implementation, selected automatically when no id is given).
 *
 * @see org.tidecloak.iga.services.IgaSystemProvisioner
 */
public interface IgaSystemProvisionerProvider extends Provider {

    /**
     * State-aware, idempotent enqueue of the tide-claims scope provisioning
     * chain (CREATE_CLIENT_SCOPE + REALM_DEFAULT_SCOPE_ADD + per-client
     * ASSIGN_SCOPE) for {@code realm}. Safe to call repeatedly. See
     * {@link org.tidecloak.iga.services.IgaSystemProvisioner#enqueueTideClaimsScopeProvisioning}.
     *
     * @param realm       the IGA-enabled target realm (caller checks enablement)
     * @param scopeRep    the {@code tide-claims} client scope representation,
     *                    including its inline {@code t.uho} protocol mapper
     * @param requestedBy the {@code REQUESTED_BY} stamp (e.g. {@code "system"})
     * @return a {@link TideUhoEnqueueResult} describing which CRs were filed
     */
    TideUhoEnqueueResult enqueueTideClaimsScopeProvisioning(
            RealmModel realm, ClientScopeRepresentation scopeRep, String requestedBy);

    /**
     * State-aware, idempotent enqueue of the tide-claims scope <em>teardown</em>
     * (a single governed {@code DELETE_CLIENT_SCOPE} CR) for {@code realm} — the
     * counterpart of {@link #enqueueTideClaimsScopeProvisioning}, invoked when a
     * realm is offboarded to local {@code /crypto} signing so the attested
     * {@code t.uho} mapper does not linger. Safe to call repeatedly. See
     * {@link org.tidecloak.iga.services.IgaSystemProvisioner#enqueueTideClaimsScopeRemoval}.
     *
     * <p>A SINGLE removal CR is sufficient: Keycloak's
     * {@code removeClientScope(realm, id)} cascade removes the realm-default, all
     * per-client attachments, the role-mapping allow-list, and the nested
     * {@code t.uho} protocol mapper in one operation — no reverse-ordered detach
     * CRs are needed.
     *
     * @param realm       the IGA-enabled target realm (caller checks enablement)
     * @param requestedBy the {@code REQUESTED_BY} stamp (e.g. {@code "system"})
     * @return a {@link TideUhoRemovalResult} describing whether a CR was filed
     *         (or that there was nothing to do)
     */
    TideUhoRemovalResult enqueueTideClaimsScopeRemoval(RealmModel realm, String requestedBy);

    /**
     * Sign-and-stamp a self-registered user's {@code user_identity} attestation unit
     * via the direct VRK:1 → Midgard → ORK ceremony, then persist the resulting bare
     * 64-byte VVK signature onto the user's {@code UserEntity.attestation} column.
     *
     * <p>This is the out-of-module entry point the {@code tidecloak-idp-extensions}
     * self-registration flow calls (verbatim, without a Maven dependency on
     * {@code iga-core}) after it has assembled the Tide blind-signature auth and the
     * gVVK-signed VendorSettings for the new user. The implementation:
     * <ol>
     *   <li>re-reads the user from {@code realm} by {@code userId} and builds the
     *       UNSIGNED {@code user_identity} envelope
     *       ({@code RealmAttestationExporter.userIdentity(user, realmId).serialize()});</li>
     *   <li>parses {@code tideAuthDataJson} (the {@code TideAuthData} JSON note) into its
     *       {@code AuthRequest} (String) + {@code BlindSig} (base64 → raw 64-byte) parts;</li>
     *   <li>constructs the midgard
     *       {@code UserIdentityAttestationUnitSignRequest}, authorizes it with the
     *       PERSISTENT gVRK authorizer triplet (AuthorizerPack-only — no Policy / doken
     *       collection), and runs {@code Midgard.SignModel} (direct VRK:1 path);</li>
     *   <li>persists {@code TIDE-FIRSTADMIN-v1:}+base64(sig) onto the user's
     *       {@code UserEntity.attestation} column (the signer-agnostic replayable shape
     *       the login read replays).</li>
     * </ol>
     *
     * <p>Fail-closed: any missing material or signing failure throws (a self-reg
     * user_identity must not be stamped with a fake signature).
     *
     * @param realm              the IGA-enabled Tide realm the user belongs to
     * @param userId             the new user's id (re-read from the session)
     * @param tideAuthDataJson   the {@code TideAuthData} JSON note encoding
     *                           {@code {AuthRequest (String), BlindSig (base64 String)}}
     * @param settingsSignedBlob the verbatim gVVK-signed VendorSettings JSON blob
     * @param settingsSigB64     base64 of the raw 64-byte settings signature
     * @return the stored bare 64-byte VVK signature bytes (the value base64-wrapped into
     *         the persisted {@code TIDE-FIRSTADMIN-v1:} column)
     */
    byte[] signAndStampUserIdentity(org.keycloak.models.RealmModel realm, String userId,
                                    String tideAuthDataJson, String settingsSignedBlob,
                                    String settingsSigB64);

    /**
     * Invite-mode counterpart of {@link #signAndStampUserIdentity}: sign-and-stamp an
     * EXISTING admin-approved invitable user's {@code user_identity} via a REORDER ceremony
     * that captures the pre-link unit, writes the {@code vuid}/{@code tideUserKey} link
     * attributes, then captures the post-link unit — all in this call.
     *
     * <p>This is the out-of-module entry point the {@code tidecloak-idp-extensions}
     * {@code LinkTideAccount} required-action calls (verbatim, without a Maven dependency
     * on {@code iga-core}) on the self-reg-OFF invite path. The caller supplies the
     * {@code userPublic} (tideUserKey) so the implementation writes the link attributes
     * itself (rather than relying on the caller having written them first). Unlike the
     * self-reg call (which signs a single fresh envelope), the invite ceremony produces and
     * ships TWO copies of the {@code user_identity}, BOTH plain UNFILTERED recomputes (no
     * attribute filtering, no sidecar table), so the ORK can prove the new unit is the
     * admin-approved one plus exactly the authenticated link:
     * <ul>
     *   <li><b>Unit A</b> — the plain unfiltered {@code user_identity} recompute taken
     *       WHILE THE ROW IS STILL PRE-LINK (before {@code vuid}/{@code tideUserKey} are
     *       written), so it byte-matches the CREATE-time bytes the stored VVK signature was
     *       made over. That signature is read (read-first, before any write) from the user's
     *       {@code UserEntity.attestation} column and shipped as {@code unitA ‖ storedSig};</li>
     *   <li><b>Unit B</b> — the plain unfiltered recompute taken AFTER the implementation
     *       writes the link attributes ({@code vuid == userId}, {@code tideUserKey ==
     *       userPublic}) onto the row, i.e. the CURRENT full state including {@code vuid}/{@code
     *       tideUserKey}. The ORK signs Unit B and the implementation OVERWRITES
     *       {@code UserEntity.attestation} with its signature so the token-time exporter
     *       (which recomputes the FULL unit) replays.</li>
     * </ul>
     *
     * <p>Fail-closed: missing material, a missing/short stored Unit A signature, parse
     * failure or a signing failure throws — an invitable user_identity must not be
     * stamped with a fake/partial signature.
     *
     * @param realm              the IGA-enabled Tide realm the user belongs to
     * @param userId             the invitable user's id (re-read from the session); also the
     *                           {@code vuid} value written onto the row
     * @param userPublic         the tideUserKey string (the {@code tideUserKey} attribute value
     *                           written onto the row; also decoded to the raw key bytes the ORK
     *                           keys the blind-sig on)
     * @param tideAuthDataJson   the {@code TideAuthData} JSON note ({@code AuthRequest} +
     *                           base64 {@code BlindSig})
     * @param settingsSignedBlob the verbatim gVVK-signed VendorSettings JSON blob
     * @param settingsSigB64     base64 of the raw 64-byte settings signature
     * @return the stored bare 64-byte VVK signature over Unit B
     */
    byte[] signAndStampInvitableUserIdentity(org.keycloak.models.RealmModel realm, String userId,
                                             String userPublic, String tideAuthDataJson,
                                             String settingsSignedBlob, String settingsSigB64);

    /**
     * Pure read: returns {@code true} iff the user's stored {@code user_identity}
     * attestation is present (the {@code UserEntity.attestation} column is non-null
     * and non-blank), i.e. the user's CREATE_USER change request has been
     * committed/replayed and stamped with the {@code TIDE-FIRSTADMIN-v1:}+base64
     * attestor signature.
     *
     * <p>This method does NOT consider whether IGA is enabled for the realm — the
     * caller gates that. Unlike the {@code signAndStamp*} methods, it is intentionally
     * not IGA-gated and never throws on an IGA-off realm; it is a side-effect-free
     * read used to gate invite-link generation on "committed" user state.
     *
     * @param realm  the realm the user belongs to
     * @param userId the user's id
     * @return {@code true} iff {@code UserEntity.attestation} is non-null and non-blank
     */
    boolean isUserIdentityCommitted(RealmModel realm, String userId);
}
