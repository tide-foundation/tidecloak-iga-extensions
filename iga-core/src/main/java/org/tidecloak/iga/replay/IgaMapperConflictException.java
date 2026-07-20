package org.tidecloak.iga.replay;

/**
 * Thrown by the commit-time replay ({@link IgaReplayDispatcher}) when a governed protocol-mapper
 * change (ADD / UPDATE) would leave a client or client-scope with TWO active access-token mappers
 * writing the SAME claim name at EQUAL priority.
 *
 * <p>Keycloak orders mappers by provider priority only ({@code ProtocolMapperUtils.compare ->
 * ProtocolMapper.getPriority}) over a {@code HashSet}, so an equal-priority, same-claim pair is
 * applied in non-deterministic iteration order — the issued token carries ONE value, which the Tide
 * ORK can match against only one of the two independently-attested mapper units. The ORK therefore
 * rejects the sign at PreSign; today TideCloak leaks that as an opaque {@code 500 unknown_error} at
 * the token endpoint (after the bad config has already committed), so the admin gets no actionable
 * signal and every login via that client fail-signs.</p>
 *
 * <p>This is a typed, structured signal (like {@link EntityVanishedException}) so the commit endpoint
 * ({@code IgaAdminResource.commitResolved}) can translate it into a clean {@code 409
 * MAPPER_CLAIM_CONFLICT} naming the claim + both mappers, and the admin can fix the config (give one
 * mapper a distinct priority, or remove the duplicate) before the next login. The guard runs BEFORE
 * the model write, so on a refusal nothing is persisted and the CR stays PENDING.</p>
 */
public class IgaMapperConflictException extends RuntimeException {

    private final String owner;
    private final String claim;
    private final int priority;
    private final String mapperA;
    private final String mapperB;

    public IgaMapperConflictException(String owner, String claim, int priority,
                                      String mapperA, String mapperB) {
        super("Protocol mappers '" + mapperA + "' and '" + mapperB + "' on " + owner
                + " both write access-token claim '" + claim + "' at equal priority " + priority
                + ". Mappers writing the same claim must have distinct priorities — set a different"
                + " priority on one of them, or remove/merge the duplicate.");
        this.owner = owner;
        this.claim = claim;
        this.priority = priority;
        this.mapperA = mapperA;
        this.mapperB = mapperB;
    }

    public String getOwner() {
        return owner;
    }

    public String getClaim() {
        return claim;
    }

    public int getPriority() {
        return priority;
    }

    public String getMapperA() {
        return mapperA;
    }

    public String getMapperB() {
        return mapperB;
    }
}
