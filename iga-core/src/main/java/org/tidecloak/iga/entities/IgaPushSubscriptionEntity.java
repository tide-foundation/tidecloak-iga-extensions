package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * One Web Push subscription: a single browser, on a single device, belonging to
 * one admin in one realm.
 *
 * <p><b>Why per realm.</b> An admin can hold the approver role in several realms,
 * and a realm is the unit that decides whether they should be told about a
 * change request. Keying on ({@code REALM_ID}, {@code USER_ID}) rather than on
 * the user alone means revoking someone's approver role in one realm stops the
 * notifications for that realm and leaves the others intact.</p>
 *
 * <p><b>Why the endpoint is hashed.</b> {@link #endpoint} is a push-service URL
 * and can run to hundreds of characters — too long for a unique index on the
 * databases Keycloak supports. {@link #endpointHash} is a SHA-256 of it, which
 * is what the uniqueness constraint and the lookups actually use. The full
 * endpoint is still stored because it is what we POST to.</p>
 *
 * <p><b>Lifecycle.</b> Rows are removed when the push service reports the
 * subscription gone (404/410 on send — see {@code IgaWebPushSender}), when the
 * browser re-subscribes with a new endpoint, or when the admin turns
 * notifications off. Nothing here is authoritative: losing every row costs
 * notifications, never governance state.</p>
 */
@Entity
@Table(name = "IGA_PUSH_SUBSCRIPTION")
@NamedQueries({
    @NamedQuery(
        name = "IgaPushSubscription.findByRealmAndUser",
        query = "SELECT s FROM IgaPushSubscriptionEntity s "
                + "WHERE s.realmId = :realmId AND s.userId = :userId"
    ),
    @NamedQuery(
        name = "IgaPushSubscription.findByRealmAndUsers",
        query = "SELECT s FROM IgaPushSubscriptionEntity s "
                + "WHERE s.realmId = :realmId AND s.userId IN :userIds"
    ),
    @NamedQuery(
        name = "IgaPushSubscription.findByRealmUserAndHash",
        query = "SELECT s FROM IgaPushSubscriptionEntity s "
                + "WHERE s.realmId = :realmId AND s.userId = :userId "
                + "AND s.endpointHash = :endpointHash"
    ),
    @NamedQuery(
        name = "IgaPushSubscription.deleteByHash",
        query = "DELETE FROM IgaPushSubscriptionEntity s WHERE s.endpointHash = :endpointHash"
    ),
    @NamedQuery(
        name = "IgaPushSubscription.deleteByRealmAndUser",
        query = "DELETE FROM IgaPushSubscriptionEntity s "
                + "WHERE s.realmId = :realmId AND s.userId = :userId"
    )
})
public class IgaPushSubscriptionEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "USER_ID", length = 36, nullable = false)
    private String userId;

    @Column(name = "ENDPOINT", columnDefinition = "TEXT", nullable = false)
    private String endpoint;

    /** SHA-256 of {@link #endpoint}, hex. Indexed; the endpoint itself is not. */
    @Column(name = "ENDPOINT_HASH", length = 64, nullable = false)
    private String endpointHash;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    /**
     * When a send to this subscription last failed in a way that is not fatal
     * (a 5xx from the push service, a timeout). Purely diagnostic - a fatal
     * 404/410 deletes the row rather than recording anything.
     */
    @Column(name = "LAST_FAILURE_AT")
    private Long lastFailureAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getEndpointHash() {
        return endpointHash;
    }

    public void setEndpointHash(String endpointHash) {
        this.endpointHash = endpointHash;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public Long getLastFailureAt() {
        return lastFailureAt;
    }

    public void setLastFailureAt(Long lastFailureAt) {
        this.lastFailureAt = lastFailureAt;
    }
}
