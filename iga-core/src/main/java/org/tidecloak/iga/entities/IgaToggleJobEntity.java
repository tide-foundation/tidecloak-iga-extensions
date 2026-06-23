package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * Persistent progress record for a single IGA toggle-on job.
 *
 * <p>The admin-ui generates a {@code jobId} (uuid) and sends it in the
 * {@code toggle-iga} POST body. While the (synchronous) toggle-on work runs,
 * the {@code TideAdminCompatResource.toggleIga} handler writes live progress
 * to this row in INDEPENDENTLY-COMMITTED sub-transactions (one
 * {@code runJobInTransaction} per stage transition) so a concurrent poll of
 * {@code GET .../toggle-iga/status/{jobId}} on another request/node sees the
 * progress mid-flight. The toggle POST itself still returns its normal body at
 * the end.</p>
 *
 * <p>{@link #stagesJson} holds the full serialized stages array (the exact
 * shape the status endpoint returns); {@link #errorJson} holds the serialized
 * {@code {stageId,message}} object or is null. {@link #state} is one of
 * {@code running|completed|failed}.</p>
 *
 * <p>Old rows are lazily reaped (rows whose {@code UPDATED_AT} is older than a
 * few hours) via the {@code IgaToggleJob.deleteOlderThan} named query — see
 * {@code IgaToggleJobService}.</p>
 */
@Entity
@Table(name = "IGA_TOGGLE_JOB")
@NamedQueries({
    @NamedQuery(
        name = "IgaToggleJob.deleteOlderThan",
        query = "DELETE FROM IgaToggleJobEntity j WHERE j.updatedAt < :cutoff"
    )
})
public class IgaToggleJobEntity {

    @Id
    @Column(name = "JOB_ID", length = 36)
    private String jobId;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "STATE", length = 20, nullable = false)
    private String state;

    @Column(name = "CURRENT_STAGE_ID", length = 64)
    private String currentStageId;

    @Column(name = "STAGES_JSON", columnDefinition = "TEXT", nullable = false)
    private String stagesJson;

    @Column(name = "ERROR_JSON", columnDefinition = "TEXT")
    private String errorJson;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "UPDATED_AT", nullable = false)
    private Long updatedAt;

    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getState() { return state; }
    public void setState(String state) { this.state = state; }

    public String getCurrentStageId() { return currentStageId; }
    public void setCurrentStageId(String currentStageId) { this.currentStageId = currentStageId; }

    public String getStagesJson() { return stagesJson; }
    public void setStagesJson(String stagesJson) { this.stagesJson = stagesJson; }

    public String getErrorJson() { return errorJson; }
    public void setErrorJson(String errorJson) { this.errorJson = errorJson; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
