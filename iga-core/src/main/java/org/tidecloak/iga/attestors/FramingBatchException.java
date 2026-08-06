package org.tidecloak.iga.attestors;

/**
 * Thrown when a multiAdmin approval carrier can no longer be trusted to describe the state
 * being committed.
 *
 * <p>A carrier's unit bytes are frozen when the enclave frames them, so phase 1 frames them
 * over the state after every currently-approvable PENDING change request that perturbs the
 * same owner set (the framing batch). That framing only holds while the batch is intact and
 * applies in one operation. Two conditions break it:
 *
 * <ul>
 *   <li>{@link #CODE_BATCH_BROKEN}: a member of the framed batch was denied, blocked,
 *       expired, re-framed into another batch, or committed on its own, so the remaining
 *       carriers describe a state that will never exist.</li>
 *   <li>{@link #CODE_UNIT_HASH_MISMATCH}: the units re-derived from the committed model do
 *       not hash to what the carrier framed. This is the byte-provenance check and it is the
 *       backstop for every ordering hazard the batch bookkeeping does not model.</li>
 * </ul>
 *
 * <p>Both are fail-closed: the commit transaction rolls back, nothing is applied, and the
 * batch's carriers are invalidated so the admin re-approves and the framing is rebuilt
 * against the current state.
 */
public final class FramingBatchException extends RuntimeException {

    /** A member of the framed batch is no longer part of it. */
    public static final String CODE_BATCH_BROKEN = "FRAMING_BATCH_BROKEN";

    /** The committed model does not re-derive the unit bytes the carrier framed. */
    public static final String CODE_UNIT_HASH_MISMATCH = "FRAMED_UNIT_HASH_MISMATCH";

    private final String code;
    private final String batchId;
    private final String changeRequestId;

    public FramingBatchException(String code, String batchId, String changeRequestId, String detail) {
        super(code + ": change request " + changeRequestId + " (framing batch " + batchId + "): " + detail);
        this.code = code;
        this.batchId = batchId;
        this.changeRequestId = changeRequestId;
    }

    public String getCode() {
        return code;
    }

    public String getBatchId() {
        return batchId;
    }

    public String getChangeRequestId() {
        return changeRequestId;
    }
}
