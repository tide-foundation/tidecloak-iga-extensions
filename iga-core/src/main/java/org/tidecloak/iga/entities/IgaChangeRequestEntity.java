package org.tidecloak.iga.entities;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "IGA_CHANGE_REQUEST")
@NamedQueries({
    @NamedQuery(
        name = "IgaChangeRequest.findPendingByEntity",
        query = "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.entityType = :entityType AND cr.entityId = :entityId AND cr.status = 'PENDING'"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.findPendingByRealm",
        query = "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.status = 'PENDING' ORDER BY cr.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.countPendingByEntity",
        query = "SELECT COUNT(cr) FROM IgaChangeRequestEntity cr WHERE cr.entityType = :entityType AND cr.entityId = :entityId AND cr.status = 'PENDING'"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.deleteByRealm",
        query = "DELETE FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId"
    )
})
public class IgaChangeRequestEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "ENTITY_TYPE", length = 50, nullable = false)
    private String entityType;

    @Column(name = "ENTITY_ID", length = 36, nullable = false)
    private String entityId;

    @Column(name = "ACTION_TYPE", length = 50, nullable = false)
    private String actionType;

    @Column(name = "ROWS_JSON", columnDefinition = "TEXT", nullable = false)
    private String rowsJson;

    @Column(name = "STATUS", length = 20, nullable = false)
    private String status;

    @Column(name = "REQUESTED_BY", length = 36)
    private String requestedBy;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "RESOLVED_AT")
    private Long resolvedAt;

    @Column(name = "RESOLVED_BY", length = 36)
    private String resolvedBy;

    /**
     * Prerequisite CR-dependency list. Comma-separated list of CR ids that MUST
     * be APPROVED before this CR may be committed (the commit path enforces a
     * 412 PRECONDITION_FAILED otherwise — see {@code IgaAdminResource.commit}).
     *
     * <p>Stored as a {@code TEXT} comma-separated string (CR ids are
     * canonical 36-char UUIDs, no commas), serialized/parsed via
     * {@link #getDependsOnList()}/{@link #setDependsOnList(java.util.List)}. A
     * comma-separated TEXT column (rather than JSON) is sufficient because the
     * elements are fixed-shape UUIDs and the list is small (1 element today —
     * the CREATE_CLIENT_SCOPE prerequisite of a REALM_DEFAULT_SCOPE_ADD /
     * ASSIGN_SCOPE), and it keeps the read path a trivial split with no JSON
     * dependency in the hot commit gate. {@code null}/empty = no prerequisites.</p>
     */
    @Column(name = "DEPENDS_ON", columnDefinition = "TEXT")
    private String dependsOn;

    /**
     * The serialized Midgard {@code Policy:1} {@link org.midgard.models.ModelRequest}
     * carrier for a multiAdmin approval ceremony (M1 two-phase doken collection).
     *
     * <p>Stored as the Base64 of {@code ModelRequest.Encode()}. Its lifecycle is the
     * two-phase round-trip with the admin's browser enclave (Heimdall):
     * <ol>
     *   <li><b>Phase 1</b> ({@code TideAttestor.buildMultiAdminApprovalModel}) writes
     *       the freshly-built {@code Policy:1} request here — the action's draft (the
     *       same producer unit-CBOR the firstAdmin path signs) wrapped in a
     *       {@code ModelRequest}, with the M0 admin {@link IgaRolePolicyEntity#getPolicy()}
     *       Policy set on it ({@code SetPolicy}) and the VRK creation-authorization
     *       attached. The admin-UI fetches it (GET .../approval-model) and hands ONLY
     *       the serialized request to the enclave.</li>
     *   <li><b>Phase 2</b> ({@code TideAttestor.acceptMultiAdminApprovalModel}) accepts
     *       the doken-embedded serialized request back (POST .../approval-model),
     *       validates it parses, and overwrites this column with the doken-embedded
     *       bytes. The policy is NOT re-set on accept-back — that would invalidate the
     *       embedded doken (mirrors the gold-reference {@code MultiAdmin.commit}, which
     *       deliberately skips {@code SetPolicy} for the already-doken'd model).</li>
     * </ol>
     *
     * <p>{@code TEXT} (nullable) — Base64 of a CBOR-ish request, larger than a UUID;
     * NULL = no approval ceremony has begun (every firstAdmin / Tideless / pre-M1 CR).
     * Only ever populated for multiAdmin-mode CRs; the firstAdmin single-phase path
     * never touches it.
     */
    @Column(name = "REQUEST_MODEL", columnDefinition = "TEXT")
    private String requestModel;

    @OneToMany(mappedBy = "changeRequest", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IgaAuthorizationEntity> authorizations = new ArrayList<>();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public String getRowsJson() { return rowsJson; }
    public void setRowsJson(String rowsJson) { this.rowsJson = rowsJson; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Long resolvedAt) { this.resolvedAt = resolvedAt; }

    public String getResolvedBy() { return resolvedBy; }
    public void setResolvedBy(String resolvedBy) { this.resolvedBy = resolvedBy; }

    public String getDependsOn() { return dependsOn; }
    public void setDependsOn(String dependsOn) { this.dependsOn = dependsOn; }

    public String getRequestModel() { return requestModel; }
    public void setRequestModel(String requestModel) { this.requestModel = requestModel; }

    /**
     * Parse {@link #dependsOn} into a list of prerequisite CR ids. Returns an
     * empty (mutable) list when there are no prerequisites.
     */
    public List<String> getDependsOnList() {
        List<String> out = new ArrayList<>();
        if (dependsOn == null || dependsOn.isBlank()) return out;
        for (String part : dependsOn.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) out.add(trimmed);
        }
        return out;
    }

    /**
     * Set {@link #dependsOn} from a list of prerequisite CR ids. A null/empty
     * list clears the column to {@code null}.
     */
    public void setDependsOnList(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            this.dependsOn = null;
            return;
        }
        this.dependsOn = String.join(",", ids);
    }

    public List<IgaAuthorizationEntity> getAuthorizations() { return authorizations; }
    public void setAuthorizations(List<IgaAuthorizationEntity> authorizations) { this.authorizations = authorizations; }
}
