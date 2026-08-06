package org.tidecloak.iga.attestors;

/**
 * Thrown when the post-stamp verification of a per-(table, owner) SET unit fails:
 * i.e. the signature stored in the owner set's {@code ATTESTATION} column is not the
 * signature this commit computed over the owner's COMMITTED member set.
 *
 * <p>The owner-keyed fan-out
 * ({@code IgaReplayDispatcher#stampOwnerSetFanOut}) overwrites EVERY row of an owner's
 * set with one signature and carries no member predicate, so a second write against the
 * same owner replaces the first. When two writes against one owner sign DIFFERENT member
 * sets (a stale pre-change read, or two change requests applied in one transaction), the
 * surviving column commits to a set the database no longer holds. The ork
 * {@code TokenValidationEngine} re-derives the committed set at token issue and rejects
 * the mismatch with {@code Attested unit signature validation failed}, an unusable realm
 * discovered at LOGIN, long after the commit that broke it.
 *
 * <p>This exception makes that condition fail at COMMIT instead. It names the unit type
 * and the owner/target id so the offending set is identifiable without reproducing the
 * batch. The commit transaction rolls back, so nothing is applied and the change request
 * stays PENDING.
 */
public final class SetUnitAttestationException extends RuntimeException {

    private final String unitType;
    private final String targetId;

    public SetUnitAttestationException(String unitType, String targetId, String realmName,
                                       String detail) {
        super("IGA set-unit attestation verification failed: unit " + unitType + " target "
                + targetId + " in realm " + realmName + ": " + detail);
        this.unitType = unitType;
        this.targetId = targetId;
    }

    public String getUnitType() {
        return unitType;
    }

    public String getTargetId() {
        return targetId;
    }
}
