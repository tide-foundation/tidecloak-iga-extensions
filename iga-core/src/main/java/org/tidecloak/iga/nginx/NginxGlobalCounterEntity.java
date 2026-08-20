package org.tidecloak.iga.nginx;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The cluster-wide DESIRED generation of the private nginx configuration — the version of the whole
 * config, not of any one realm. One row, always {@link #SINGLETON_ID}, so every replica reads the
 * same number for the same intended configuration.
 *
 * <p>What a given replica's nginx is actually serving is node-local memory and must never be stored
 * here: reconciliation is each node independently closing the gap between this shared value and its
 * own applied one, and the nodes converge at different moments.
 *
 * <p>Not an IGA object — no change request, no approval. The approval that mattered already
 * happened on the state this generation describes.
 */
@Entity
@Table(name = "NGINX_GLOBAL_COUNTER")
public class NginxGlobalCounterEntity {

    public static final String SINGLETON_ID = "GLOBAL";

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    /** Starts at 0 (nothing ever requested); the first allocation yields 1. */
    @Column(name = "COUNTER", nullable = false)
    private long counter;

    @Column(name = "UPDATED_AT")
    private Long updatedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }

}
