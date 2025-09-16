package org.tidecloak.base.iga.interfaces.models;
import jakarta.persistence.*;
import java.time.OffsetDateTime;

/** Stores a single preview request + results (baseline/preview/diff). */
@Entity
@Table(name = "TIDE_TOKEN_PREVIEW")
public class TokenPreviewEntity {

    @Id
    @Column(name = "ID", length = 36, nullable = false, updatable = false)
    public String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    public String realmId;

    @Column(name = "USER_ID", length = 36)
    public String userId;

    @Column(name = "CLIENT_ID", length = 255, nullable = false)
    public String clientId;

    @Column(name = "CREATED_AT", nullable = false)
    public OffsetDateTime createdAt;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "SPEC_JSON", columnDefinition = "TEXT")
    public String specJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "BASELINE_JSON", columnDefinition = "TEXT")
    public String baselineJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "PREVIEW_JSON", columnDefinition = "TEXT")
    public String previewJson;

    @Lob @Basic(fetch = FetchType.LAZY)
    @Column(name = "DIFF_JSON", columnDefinition = "TEXT")
    public String diffJson;

    public TokenPreviewEntity() {}
}

