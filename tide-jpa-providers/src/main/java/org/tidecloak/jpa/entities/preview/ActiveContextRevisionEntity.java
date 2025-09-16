package org.tidecloak.jpa.entities.preview;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

/**
 * Tracks the realm-level active context revision used for optimistic rebasing
 * of token previews after commits.
 */
@Entity
@Table(name = "tide_active_context_revision")
public class ActiveContextRevisionEntity {

    @Id
    @Column(name = "realm_id", length = 36, nullable = false, updatable = false)
    public String realmId;

    @Column(name = "active_rev", nullable = false)
    public long activeRev = 0L;

    @Column(name = "updated_at", nullable = false)
    public OffsetDateTime updatedAt = OffsetDateTime.now();

    public ActiveContextRevisionEntity() {}

    public ActiveContextRevisionEntity(String realmId, long activeRev) {
        this.realmId = realmId;
        this.activeRev = activeRev;
        this.updatedAt = OffsetDateTime.now();
    }
}
