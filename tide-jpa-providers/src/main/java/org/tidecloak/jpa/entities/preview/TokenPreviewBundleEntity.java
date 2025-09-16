package org.tidecloak.jpa.entities.preview;


import jakarta.persistence.*;
import java.time.OffsetDateTime;

/**
 * Records a bundle request (merged + standalone previews).
 */
@Entity
@Table(name = "tide_token_preview_bundle",
       indexes = @Index(name = "idx_ttpb_realm_created", columnList = "realm_id,created_at"))
public class TokenPreviewBundleEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    public String id;

    @Column(name = "realm_id", length = 36, nullable = false)
    public String realmId;

    @Column(name = "created_at", nullable = false)
    public OffsetDateTime createdAt = OffsetDateTime.now();

    @Column(name = "iga_mode", length = 16, nullable = false)
    public String igaMode; // "TIDE-IGA" or "BASIC-IGA" (label only)

    @Column(name = "item_count", nullable = false)
    public int itemCount;

    @Column(name = "merged_count", nullable = false)
    public int mergedCount;

    @Column(name = "standalone_count", nullable = false)
    public int standaloneCount;

    @Lob @Column(name = "items_json", nullable = false)
    public String itemsJson;

    @Lob @Column(name = "merged_json", nullable = false)
    public String mergedJson;

    @Lob @Column(name = "preview_ids_json", nullable = false)
    public String previewIdsJson;

    @Lob @Column(name = "conflicts_json", nullable = false)
    public String conflictsJson;

    public TokenPreviewBundleEntity() {}
}
