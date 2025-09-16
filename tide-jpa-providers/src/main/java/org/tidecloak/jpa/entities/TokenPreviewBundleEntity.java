package org.tidecloak.base.iga.interfaces.models;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

/** Stores a bundle operation (merged/standalone items + created preview IDs). */
@Entity
@Table(name = "TIDE_TOKEN_PREVIEW_BUNDLE")
public class TokenPreviewBundleEntity {

    @Id
    @Column(name = "ID", length = 36, nullable = false, updatable = false)
    public String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    public String realmId;

    @Column(name = "CREATED_AT", nullable = false)
    public OffsetDateTime createdAt;

    @Column(name = "IGA_MODE", length = 32, nullable = false)
    public String igaMode; // "TIDE-IGA" or "BASIC-IGA" (string for audit)

    @Column(name = "ITEM_COUNT")
    public int itemCount;

    @Column(name = "MERGED_COUNT")
    public int mergedCount;

    @Column(name = "STANDALONE_COUNT")
    public int standaloneCount;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "ITEMS_JSON", columnDefinition = "TEXT")
    public String itemsJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "MERGED_JSON", columnDefinition = "TEXT")
    public String mergedJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "PREVIEW_IDS_JSON", columnDefinition = "TEXT")
    public String previewIdsJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "CONFLICTS_JSON", columnDefinition = "TEXT")
    public String conflictsJson;

    public TokenPreviewBundleEntity() {}
}
