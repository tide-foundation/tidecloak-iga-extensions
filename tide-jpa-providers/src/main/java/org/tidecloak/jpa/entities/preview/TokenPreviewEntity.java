package org.tidecloak.jpa.entities.preview;


import jakarta.persistence.*;
import java.time.OffsetDateTime;

/**
 * Stores an individual token preview run for a user+client (or default-client context).
 * JSON columns are stored as CLOB for portability across DBs.
 */
@Entity
@Table(name = "tide_token_preview",
       indexes = {
           @Index(name = "idx_ttp_realm_user_client_created", columnList = "realm_id,user_id,client_id,created_at"),
           @Index(name = "idx_ttp_realm_created", columnList = "realm_id,created_at")
       })
public class TokenPreviewEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    public String id;

    @Column(name = "realm_id", length = 36, nullable = false)
    public String realmId;

    @Column(name = "user_id", length = 36)
    public String userId; // can be null for default-client context

    @Column(name = "client_id", length = 36, nullable = false)
    public String clientId;

    @Column(name = "created_at", nullable = false)
    public OffsetDateTime createdAt = OffsetDateTime.now();

    @Lob @Column(name = "spec_json", nullable = false)
    public String specJson;

    @Lob @Column(name = "baseline_json", nullable = false)
    public String baselineJson;

    @Lob @Column(name = "preview_json", nullable = false)
    public String previewJson;

    @Lob @Column(name = "diff_json", nullable = false)
    public String diffJson;

    public TokenPreviewEntity() {}
}
