package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The realm's VAPID key pair for approval push notifications.
 *
 * <p><b>Why a table and not a realm attribute.</b> The obvious place for two
 * strings keyed by realm is {@code realm.setAttribute}, and that is wrong here:
 * realm attributes are governed state. Under IGA a write to one is captured as
 * a {@code SET_REALM_ATTRIBUTE} change request instead of being applied, so the
 * key pair never lands, the endpoint that generated it hands out a key that is
 * immediately forgotten, and the realm accumulates a change request nobody
 * asked for. The second call then fails outright against the pending CR.</p>
 *
 * <p>These keys are operational, not governance: they authenticate this server
 * to a push service and no approval decision depends on them. They must not
 * pass through the approval pipeline, so they live in their own table where
 * writes simply apply. Keeping them out of realm attributes also keeps them out
 * of the realm representation, which anyone who can view the realm can read.</p>
 *
 * <p>One row per realm, created on first subscribe. Never rotated in place: the
 * public half is baked into every subscription a browser has already made, so
 * replacing it silently breaks all of them.</p>
 */
@Entity
@Table(name = "IGA_PUSH_VAPID")
public class IgaVapidKeyEntity {

    @Id
    @Column(name = "REALM_ID", length = 36)
    private String realmId;

    /** Base64url (unpadded) uncompressed P-256 point, 65 bytes. */
    @Column(name = "PUBLIC_KEY", length = 255, nullable = false)
    private String publicKey;

    /** Base64 of the PKCS#8 encoding. */
    @Column(name = "PRIVATE_KEY", columnDefinition = "TEXT", nullable = false)
    private String privateKey;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
}
