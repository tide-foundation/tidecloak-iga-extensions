package org.tidecloak.iga.providers;

import jakarta.persistence.EntityManager;
import org.tidecloak.iga.entities.IgaPushSubscriptionEntity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Storage for Web Push subscriptions.
 *
 * <p>Deliberately thin: subscriptions are disposable. Nothing in governance
 * depends on a row here surviving, so every operation is written to be safely
 * repeatable rather than carefully transactional.</p>
 */
public class IgaPushSubscriptionService {

    private final EntityManager em;

    public IgaPushSubscriptionService(EntityManager em) {
        this.em = em;
    }

    /**
     * Record a subscription for this admin in this realm.
     *
     * <p>Idempotent by (realm, user, endpoint): a browser that re-subscribes
     * with the same endpoint updates the existing row rather than adding a
     * second one, which is what happens on every service-worker update.</p>
     */
    public IgaPushSubscriptionEntity upsert(String realmId, String userId, String endpoint) {
        String hash = sha256Hex(endpoint);

        List<IgaPushSubscriptionEntity> existing = em
                .createNamedQuery("IgaPushSubscription.findByRealmUserAndHash",
                        IgaPushSubscriptionEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .setParameter("endpointHash", hash)
                .getResultList();

        if (!existing.isEmpty()) {
            IgaPushSubscriptionEntity row = existing.get(0);
            row.setEndpoint(endpoint);
            row.setLastFailureAt(null);
            em.flush();
            return row;
        }

        IgaPushSubscriptionEntity row = new IgaPushSubscriptionEntity();
        row.setId(UUID.randomUUID().toString());
        row.setRealmId(realmId);
        row.setUserId(userId);
        row.setEndpoint(endpoint);
        row.setEndpointHash(hash);
        row.setCreatedAt(System.currentTimeMillis());
        em.persist(row);
        em.flush();
        return row;
    }

    /** Every subscription belonging to any of {@code userIds} in this realm. */
    public List<IgaPushSubscriptionEntity> findForUsers(String realmId, Collection<String> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return List.of();
        }
        return em.createNamedQuery("IgaPushSubscription.findByRealmAndUsers",
                        IgaPushSubscriptionEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("userIds", userIds)
                .getResultList();
    }

    public List<IgaPushSubscriptionEntity> findForUser(String realmId, String userId) {
        return em.createNamedQuery("IgaPushSubscription.findByRealmAndUser",
                        IgaPushSubscriptionEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .getResultList();
    }

    /**
     * Forget a dead endpoint, in every realm that referenced it.
     *
     * <p>Not scoped to a realm on purpose: a 404/410 from the push service means
     * the browser subscription itself is gone, so it is dead everywhere it was
     * recorded, not only for the realm whose send happened to discover it.</p>
     */
    public int deleteByEndpoint(String endpoint) {
        return em.createNamedQuery("IgaPushSubscription.deleteByHash")
                .setParameter("endpointHash", sha256Hex(endpoint))
                .executeUpdate();
    }

    /** Turn notifications off for this admin in this realm. */
    public int deleteForUser(String realmId, String userId) {
        return em.createNamedQuery("IgaPushSubscription.deleteByRealmAndUser")
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .executeUpdate();
    }

    static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory on every JVM this runs on.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
