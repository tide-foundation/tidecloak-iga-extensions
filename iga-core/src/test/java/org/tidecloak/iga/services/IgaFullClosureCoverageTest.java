package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.spi.UnitColumnMapping;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.ParentType;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;

import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ★ Complete-coverage stamping (root fix) — every login-emitted unit an entity owns gets a
 * REAL 64B VVK sig on approval, BY CONSTRUCTION (producer enumeration, not a hand-listed
 * subset).
 *
 * <p>The bug this pins: the hand-coded per-unit-type ADOPT stampers
 * ({@code TideAttestor.stampProducerUnitColumns} ADOPT cases) were INCOMPLETE — after a
 * bulk-approve on a fresh capable firstAdmin realm, {@code role_composite_children_set} (ALL
 * 32B {@code TIDE-DUMMY} stub) and 23/39 {@code protocol_mapper} columns stayed STUB/NULL, so
 * the uniform login read fail-closed on {@code role_composite_children_set}.
 *
 * <p>The fix re-uses the PROVEN-COMPLETE {@link IgaToggleOnBackfill} producer enumeration
 * (the SAME {@code RealmAttestationExporter.export -> signEnvelopesWithFirstAdminVvk ->
 * UnitColumnMapping.stamp} closure the login read consumes), triggered at the admin's
 * APPROVAL (single + bulk commit) once the realm is fully-adopted. Because the producer emits
 * EVERY unit type (including system units — {@code RealmAttestationExporter.export} does NOT
 * apply {@code IgaSystemEntityFilter}) and {@link UnitColumnMapping#stamp} has a column for
 * EVERY type, every login-emitted unit is stamped REAL by construction.
 *
 * <p>The load-bearing assertions:
 * <ol>
 *   <li><b>Complete column coverage.</b> For EVERY one of the 18 {@link AttestationUnitType}
 *       values, {@link UnitColumnMapping#stamp} stamps a real 64B {@code FIRSTADMIN}-prefixed
 *       sig into that type's dedicated column with NO {@code IllegalStateException} ("no
 *       column stamp for unit type"). A missing branch — the original gap that left
 *       {@code role_composite_children_set} / {@code protocol_mapper} stub — fails the build.
 *       The two regression-critical types are asserted explicitly.</li>
 *   <li><b>Idempotency discriminator.</b> Only a {@code FIRSTADMIN}+64B value counts as
 *       already-real (skip, never clobber); NULL / stub / wrong-len is (re)signed.</li>
 *   <li><b>Gated + fail-closed.</b> {@code convergeAfterCommit} is a no-op (skipped) unless the
 *       realm is firstAdmin + real-signing-capable, and defers while ADOPT CRs pend.</li>
 * </ol>
 */
class IgaFullClosureCoverageTest {

    private static final String REALM_ID = "realm-coverage-uuid";

    /** A REAL 64-byte firstAdmin VVK sig string — the shape the uniform login read replays. */
    private static String real64() {
        return TideAttestor.FIRSTADMIN_SIG_PREFIX
                + Base64.getEncoder().encodeToString(new byte[64]);
    }

    /** An EntityManager whose every UPDATE/JPQL returns 1 row affected, capturing the sig param. */
    private static final class CapturingEm {
        final EntityManager em = mock(EntityManager.class);
        final List<String> jpqls = new ArrayList<>();
        final List<Query> queries = new ArrayList<>();

        /** The value bound to the {@code :sig} JPQL parameter across all queries this pass. */
        String captureSig() {
            for (Query q : queries) {
                for (org.mockito.invocation.Invocation in :
                        org.mockito.Mockito.mockingDetails(q).getInvocations()) {
                    Object[] args = in.getArguments();
                    if ("setParameter".equals(in.getMethod().getName())
                            && args.length == 2
                            && "sig".equals(args[0])) {
                        return String.valueOf(args[1]);
                    }
                }
            }
            return null;
        }

        CapturingEm() {
            lenient().when(em.createQuery(anyString())).thenAnswer(inv -> {
                jpqls.add(inv.getArgument(0));
                // RETURNS_SELF makes the fluent setParameter/setMaxResults chain return the
                // mock without per-overload stubbing (which otherwise trips Mockito's generic
                // setParameter overload resolution and throws a spurious ClassCast). We then
                // override only executeUpdate / getResultList, and capture the :sig param via
                // a Mockito verify+captor AFTER the call (see captureSig()).
                Query q = mock(Query.class, org.mockito.Answers.RETURNS_SELF);
                lenient().when(q.executeUpdate()).thenReturn(1);
                lenient().when(q.getResultList()).thenReturn(new ArrayList<>());
                queries.add(q);
                return q;
            });
        }
    }

    /**
     * A minimal {@link AttestationUnit} stand-in for the types whose only inputs to
     * {@link UnitColumnMapping#stamp} are {@code type()} + {@code targetId()} (all 17 of the 18
     * except SCOPE_ROLE_ALLOWLIST_SET, which the mapping casts to its concrete class).
     */
    private static AttestationUnit unitOfType(AttestationUnitType type) {
        AttestationUnit u = mock(AttestationUnit.class);
        lenient().when(u.type()).thenReturn(type);
        lenient().when(u.targetId()).thenReturn("target-" + type.name());
        return u;
    }

    private static AttestationUnit representative(AttestationUnitType type) {
        if (type == AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET) {
            // The ONLY type UnitColumnMapping.stamp downcasts — needs the real class.
            return new ScopeRoleAllowlistSetUnit(REALM_ID, ParentType.client,
                    "client-uuid-target", List.of("role-a", "role-b"));
        }
        return unitOfType(type);
    }

    /**
     * ★ EVERY login-emitted unit type stamps a REAL 64B firstAdmin sig into its dedicated
     * column — no type is un-stampable. A missing branch (the original gap) throws
     * {@code IllegalStateException} from {@link UnitColumnMapping#stamp} and fails the build.
     *
     * <p>The closure grew from 18 to 19 with D1a's {@code realm_default_roles_set} (ordinal 18,
     * appended at the end of the ork enum); it maps to
     * {@code RealmEntity.realmDefaultRolesAttestation} (parallel to unit 15
     * {@code realm_default_groups_set}).
     */
    @Test
    void allEighteenUnitTypes_stampARealSixtyFourByteColumn_byConstruction() {
        assertEquals(19, AttestationUnitType.values().length,
                "the login closure is 19 unit types (ork enum 0..18, realm_default_roles_set "
                        + "appended at 18); a new type MUST get a UnitColumnMapping stamp branch "
                        + "or it would silently stay NULL");

        String realSig = real64();
        Set<AttestationUnitType> stamped = EnumSet.noneOf(AttestationUnitType.class);

        for (AttestationUnitType type : AttestationUnitType.values()) {
            CapturingEm cap = new CapturingEm();
            int rows;
            try {
                rows = UnitColumnMapping.stamp(cap.em, representative(type), realSig);
            } catch (IllegalStateException missingBranch) {
                fail("UnitColumnMapping.stamp has NO column for unit type " + type
                        + " — it would stay NULL/stub and fail-close the login read: "
                        + missingBranch.getMessage());
                return;
            }
            assertTrue(rows > 0,
                    "type " + type + " must stamp at least one owner row");
            String stampedSig = cap.captureSig();
            assertNotNull(stampedSig, "type " + type + " must bind the :sig parameter");
            assertEquals(realSig, stampedSig,
                    "type " + type + " must stamp the REAL 64B firstAdmin sig verbatim");
            // The stamped value is a real, replayable firstAdmin sig (the login read's gate).
            assertTrue(IgaToggleOnBackfill.isRealReplayableSig(stampedSig),
                    "type " + type + " must stamp a value the uniform login read accepts (64B firstAdmin)");
            stamped.add(type);
        }

        assertEquals(EnumSet.allOf(AttestationUnitType.class), stamped,
                "ALL 18 unit types must be stampable with a real 64B sig — none may be left un-stamped");
    }

    /**
     * The two regression-critical types that the hand-coded path left stub/NULL — pinned
     * explicitly so a regression names them directly.
     */
    @Test
    void compositeRoleAndProtocolMapper_areStampedReal_notStub() {
        for (AttestationUnitType type : List.of(
                AttestationUnitType.ROLE_COMPOSITE_CHILDREN_SET,
                AttestationUnitType.PROTOCOL_MAPPER)) {
            CapturingEm cap = new CapturingEm();
            int rows = UnitColumnMapping.stamp(cap.em, representative(type), real64());
            assertTrue(rows > 0, type + " must stamp its column (was the stub/NULL gap)");
            String stampedSig = cap.captureSig();
            assertNotNull(stampedSig, type + " must bind the :sig parameter");
            byte[] body = Base64.getDecoder().decode(
                    stampedSig.substring(TideAttestor.FIRSTADMIN_SIG_PREFIX.length()));
            assertEquals(64, body.length,
                    type + " must carry a REAL 64-byte VVK sig — NOT the 32B TIDE-DUMMY/SHA-256 stub");
        }
    }

    /**
     * Idempotency: the convergence pass only (re)signs NULL / stub / wrong-length columns; a
     * real 64B firstAdmin sig is left untouched. This is the exact discriminator the uniform
     * login read uses, so a column the pass leaves un-resigned is one the read can replay.
     */
    @Test
    void idempotency_onlyNullOrStubColumnsGetReSigned() {
        assertTrue(IgaToggleOnBackfill.isRealReplayableSig(real64()),
                "a real 64B firstAdmin sig is already-covered (skip, never clobber)");
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(null), "NULL → (re)sign");
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(
                        TideAttestor.FIRSTADMIN_SIG_PREFIX
                                + Base64.getEncoder().encodeToString(new byte[32])),
                "the 32B TIDE-DUMMY/SHA-256 STUB → (re)sign");
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(
                        "TIDE-DUMMY-v1:" + Base64.getEncoder().encodeToString(new byte[64])),
                "a wrong-prefix (multiAdmin dummy) value → (re)sign");
    }

    /**
     * Gated: the post-commit convergence is a no-op unless the realm is firstAdmin AND
     * real-signing-capable. A realm with no tide-vendor-key (the unit-test environment) is not
     * capable, so convergeAfterCommit short-circuits BEFORE any pending-ADOPT query or ORK
     * round-trip — proving the admin-triggered stamp never fires on dev/test or non-firstAdmin
     * realms (and never auto-signs at toggle).
     */
    @Test
    void convergeAfterCommit_isGated_noOpOnNonCapableRealm() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(mock(EntityManager.class));
        lenient().when(realm.getId()).thenReturn(REALM_ID);
        lenient().when(realm.getName()).thenReturn("coverage-realm");
        // No tide-vendor-key component → not real-signing-capable.
        lenient().when(realm.getComponentsStream())
                .thenAnswer(inv -> java.util.stream.Stream.empty());

        IgaToggleOnBackfill.Result result =
                IgaToggleOnBackfill.convergeAfterCommit(session, realm);

        assertFalse(result.ran,
                "a non-capable (no-vendor-key) realm must NOT run the full-closure stamp");
        assertEquals("not_first_admin_or_not_capable", result.skipReason);
        assertEquals(0, result.unitsSigned, "a gated-out convergence signs zero units");
    }
}
