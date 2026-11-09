package org.tidecloak.iga.providers;

import org.tidecloak.iga.entities.IgaServerCertEnrollmentTokenEntity;

import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Service for one-time server-cert enrollment tokens.
 *
 * <p>A token is minted by an admin (manage-realm) for a (realm, client). The plaintext is
 * returned to the caller ONCE and never stored — only its SHA-256 hex hash is persisted. The
 * workload then presents the plaintext on its public {@code /tide-server-identity/request}
 * call, where it is validated-and-consumed atomically (single-use). Re-minting for the same
 * (realm, client) supersedes (invalidates) any prior unconsumed token for that client.
 */
public class IgaServerCertEnrollmentTokenService {

    /** Token plaintext prefix (helps callers/log scrubbers recognise the secret). */
    private static final String TOKEN_PREFIX = "tsei_";
    private static final int RANDOM_BYTES = 32;

    private final EntityManager em;

    public IgaServerCertEnrollmentTokenService(EntityManager em) {
        this.em = em;
    }

    /** Result of a mint: the one-time plaintext (never stored) + its expiry (epoch ms). */
    public static final class MintResult {
        public final String plaintext;
        public final long expiresAt;

        public MintResult(String plaintext, long expiresAt) {
            this.plaintext = plaintext;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * Mint a new one-time enrollment token for (realmId, clientId).
     *
     * <p>FIRST supersedes any prior unconsumed token for this (realm, client) by stamping
     * their CONSUMED_AT, then generates a fresh plaintext, persists only its hash, and
     * returns the plaintext + expiry. The plaintext is NOT stored.
     *
     * @param ttlSeconds time-to-live in seconds (caller is responsible for clamping).
     */
    public MintResult mint(String realmId, String clientId, long ttlSeconds, String createdBy) {
        long now = System.currentTimeMillis();

        // Re-mint supersedes: invalidate any prior unconsumed token for this client.
        em.createQuery(
                "UPDATE IgaServerCertEnrollmentTokenEntity t SET t.consumedAt = :now "
                        + "WHERE t.realmId = :realmId AND t.clientId = :clientId AND t.consumedAt IS NULL")
                .setParameter("now", now)
                .setParameter("realmId", realmId)
                .setParameter("clientId", clientId)
                .executeUpdate();

        byte[] random = new byte[RANDOM_BYTES];
        new SecureRandom().nextBytes(random);
        String plaintext = TOKEN_PREFIX
                + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        String hash = sha256Hex(plaintext);

        long expiresAt = now + (ttlSeconds * 1000L);

        IgaServerCertEnrollmentTokenEntity entity = new IgaServerCertEnrollmentTokenEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realmId);
        entity.setClientId(clientId);
        entity.setTokenHash(hash);
        entity.setCreatedAt(now);
        entity.setExpiresAt(expiresAt);
        entity.setCreatedBy(createdBy);
        em.persist(entity);
        em.flush();

        return new MintResult(plaintext, expiresAt);
    }

    /**
     * Non-consuming validity gate: returns true iff there is a token for (realmId, clientId)
     * whose hash matches the presented plaintext, that is unconsumed and unexpired. Used to
     * gate BEFORE the CR is created, so the actual single-use consume can happen afterwards.
     */
    public boolean isValid(String realmId, String clientId, String presentedToken) {
        if (presentedToken == null || presentedToken.isEmpty()) {
            return false;
        }
        long now = System.currentTimeMillis();
        String hash = sha256Hex(presentedToken);
        Long count = em.createQuery(
                "SELECT COUNT(t) FROM IgaServerCertEnrollmentTokenEntity t "
                        + "WHERE t.realmId = :realmId AND t.clientId = :clientId AND t.tokenHash = :hash "
                        + "AND t.consumedAt IS NULL AND t.expiresAt > :now", Long.class)
                .setParameter("realmId", realmId)
                .setParameter("clientId", clientId)
                .setParameter("hash", hash)
                .setParameter("now", now)
                .getSingleResult();
        return count != null && count == 1L;
    }

    /**
     * Atomic, single-use consume. Hashes the presented plaintext and runs a conditional
     * UPDATE that consumes the row ONLY if it exists, matches the (realm, client), is
     * unconsumed and unexpired. Returns true iff exactly one row was consumed.
     *
     * <p>The conditional UPDATE is the single-use TOCTOU guard: two concurrent presents of
     * the same token race on the same row and exactly one wins (rowcount == 1).
     */
    public boolean consumeIfValid(String realmId, String clientId, String presentedToken) {
        if (presentedToken == null || presentedToken.isEmpty()) {
            return false;
        }
        long now = System.currentTimeMillis();
        String hash = sha256Hex(presentedToken);
        int updated = em.createQuery(
                "UPDATE IgaServerCertEnrollmentTokenEntity t SET t.consumedAt = :now "
                        + "WHERE t.realmId = :realmId AND t.clientId = :clientId AND t.tokenHash = :hash "
                        + "AND t.consumedAt IS NULL AND t.expiresAt > :now")
                .setParameter("now", now)
                .setParameter("realmId", realmId)
                .setParameter("clientId", clientId)
                .setParameter("hash", hash)
                .executeUpdate();
        return updated == 1;
    }

    private static String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
