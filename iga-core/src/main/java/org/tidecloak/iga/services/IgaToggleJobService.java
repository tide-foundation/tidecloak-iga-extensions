package org.tidecloak.iga.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.entities.IgaToggleJobEntity;

/**
 * Live-progress service for the synchronous IGA toggle-on.
 *
 * <p>{@code TideAdminCompatResource.toggleIga} runs the toggle-on work
 * synchronously. The slow stages (the ADOPT scan, and especially the firstAdmin
 * baseline-config auto-commit / ORK-VVK signing sweep) freeze the admin UI while
 * the POST blocks. This service persists per-stage progress for a caller-supplied
 * {@code jobId} into an {@link IgaToggleJobEntity} row so a concurrent
 * {@code GET .../toggle-iga/status/{jobId}} (potentially on a different request /
 * cluster node) can render a live checklist.</p>
 *
 * <p><b>Why independently-committed sub-transactions.</b> The toggle POST holds a
 * single request transaction for its whole (slow) duration. A poller on another
 * request would never see a progress write made inside that still-open
 * transaction. Every mutator here therefore runs its update in its OWN short
 * {@link KeycloakModelUtils#runJobInTransaction} session and commits immediately,
 * so the row is visible to a concurrent poll the instant a stage transitions.</p>
 *
 * <p>All mutators are best-effort: a progress-write failure must NEVER abort the
 * toggle (the realm attribute is already committed and the toggle's own work is
 * the source of truth). Failures are logged and swallowed.</p>
 */
public final class IgaToggleJobService {

    private static final Logger log = Logger.getLogger(IgaToggleJobService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> STAGES_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    public static final String STATE_RUNNING = "running";
    public static final String STATE_COMPLETED = "completed";
    public static final String STATE_COMPLETED_WITH_WARNINGS = "completed_with_warnings";
    public static final String STATE_FAILED = "failed";

    public static final String STATUS_WARNING = "warning";

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_RUNNING = "running";
    public static final String STATUS_DONE = "done";
    public static final String STATUS_FAILED = "failed";

    /** Lazy-cleanup horizon: rows untouched for longer than this are reaped on {@link #start}. */
    private static final long CLEANUP_AGE_MS = 6L * 60L * 60L * 1000L; // 6 hours

    private final KeycloakSessionFactory sessionFactory;

    public IgaToggleJobService(KeycloakSession session) {
        this.sessionFactory = session.getKeycloakSessionFactory();
    }

    /**
     * A single reportable stage. Immutable definition (id + label) plus mutable
     * progress (status / current / total). {@code current}/{@code total} are
     * {@code null} when the stage is not countable.
     */
    public static final class Stage {
        public final String id;
        public final String label;
        public String status;
        public Long current;
        public Long total;

        public Stage(String id, String label) {
            this.id = id;
            this.label = label;
            this.status = STATUS_PENDING;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("label", label);
            m.put("status", status);
            m.put("current", current);
            m.put("total", total);
            return m;
        }
    }

    /** Convenience factory for an ordered stage list. */
    public static List<Stage> stages(Stage... s) {
        List<Stage> out = new ArrayList<>();
        for (Stage stage : s) out.add(stage);
        return out;
    }

    /**
     * Create the job row with every stage {@code pending} and {@code state=running}
     * so the UI can render the full checklist immediately. Also lazily reaps rows
     * older than {@link #CLEANUP_AGE_MS}.
     */
    public void start(String jobId, String realmId, List<Stage> stages) {
        if (jobId == null) return;
        long now = System.currentTimeMillis();
        String stagesJson = serializeStages(stages);
        runInTx(em -> {
            // Lazy cleanup of stale rows (best-effort).
            try {
                em.createNamedQuery("IgaToggleJob.deleteOlderThan")
                        .setParameter("cutoff", now - CLEANUP_AGE_MS)
                        .executeUpdate();
            } catch (RuntimeException reapEx) {
                log.debugf(reapEx, "IGA toggle-job: lazy cleanup failed (continuing)");
            }
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) {
                job = new IgaToggleJobEntity();
                job.setJobId(jobId);
                job.setCreatedAt(now);
            }
            applyStart(job, realmId, stagesJson, now);
            em.merge(job);
        });
    }

    /** Mark a stage {@code running} (optionally seeding current/total) and set it as the current stage. */
    public void stageRunning(String jobId, String stageId, Long current, Long total) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyStageRunning(job, stageId, current, total);
            em.merge(job);
        });
    }

    /** Update the {@code current}/{@code total} counters of a (running) stage. */
    public void stageProgress(String jobId, String stageId, Long current, Long total) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyStageProgress(job, stageId, current, total);
            em.merge(job);
        });
    }

    /** Mark a stage {@code done} (optionally finalizing current/total). Clears the current-stage pointer. */
    public void stageDone(String jobId, String stageId, Long current, Long total) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyStageDone(job, stageId, current, total);
            em.merge(job);
        });
    }

    /** Mark the whole job {@code completed} (leaves run stages as-is — they are already {@code done}). */
    public void complete(String jobId) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyComplete(job);
            em.merge(job);
        });
    }

    /**
     * Mark the whole job {@code completed_with_warnings} (a non-fatal outcome:
     * the toggle succeeded but some per-entity work did not). Marks {@code stageId}
     * with a {@code warning} status and records the {@code message} in the error
     * object so the UI can render it. Like {@link #complete}, this NEVER overrides a
     * job already in the {@code failed} state — a truly-failed job stays failed
     * (a hard failure outranks a warning).
     */
    public void completeWithWarnings(String jobId, String stageId, String message) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyCompleteWithWarnings(job, stageId, message);
            em.merge(job);
        });
    }

    /**
     * Mark a stage {@code failed}, the job {@code failed}, and populate the
     * {@code error} object with {@code stageId}/{@code message}.
     */
    public void fail(String jobId, String stageId, String message) {
        if (jobId == null) return;
        runInTx(em -> {
            IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
            if (job == null) return;
            applyFail(job, stageId, message);
            em.merge(job);
        });
    }

    // ---- pure entity transitions (DB-free; the source of truth, unit-tested) ----

    /** Initialize a job entity: state=running, all stages pending (as serialized), no error. */
    static void applyStart(IgaToggleJobEntity job, String realmId, String stagesJson, long now) {
        job.setRealmId(realmId);
        job.setState(STATE_RUNNING);
        job.setCurrentStageId(null);
        job.setStagesJson(stagesJson);
        job.setErrorJson(null);
        job.setUpdatedAt(now);
    }

    static void applyStageRunning(IgaToggleJobEntity job, String stageId, Long current, Long total) {
        mutateStageEntity(job, stageId, stageId, stage -> {
            stage.put("status", STATUS_RUNNING);
            if (current != null) stage.put("current", current);
            if (total != null) stage.put("total", total);
        });
    }

    static void applyStageProgress(IgaToggleJobEntity job, String stageId, Long current, Long total) {
        mutateStageEntity(job, stageId, stageId, stage -> {
            // Keep it running; only refresh counters (never resurrect a done/failed stage).
            if (!STATUS_DONE.equals(stage.get("status")) && !STATUS_FAILED.equals(stage.get("status"))) {
                stage.put("status", STATUS_RUNNING);
            }
            if (current != null) stage.put("current", current);
            if (total != null) stage.put("total", total);
        });
    }

    static void applyStageDone(IgaToggleJobEntity job, String stageId, Long current, Long total) {
        mutateStageEntity(job, stageId, null, stage -> {
            stage.put("status", STATUS_DONE);
            if (current != null) stage.put("current", current);
            if (total != null) stage.put("total", total);
        });
    }

    static void applyComplete(IgaToggleJobEntity job) {
        // Never flip a failed job to completed (a failed sign-defaults stage
        // leaves the job failed even though the toggle still returns 200).
        if (STATE_RUNNING.equals(job.getState())) {
            job.setState(STATE_COMPLETED);
            job.setCurrentStageId(null);
        }
        job.setUpdatedAt(System.currentTimeMillis());
    }

    /**
     * Mark a stage {@code warning}, set the job state to
     * {@code completed_with_warnings}, and record the warning in the error object.
     * Mirrors {@link #applyComplete}: only a {@code running} job is advanced, so a
     * job already {@code failed} (a hard failure) is left untouched and a warning
     * never downgrades it.
     */
    static void applyCompleteWithWarnings(IgaToggleJobEntity job, String stageId, String message) {
        if (!STATE_RUNNING.equals(job.getState())) {
            // Already failed (hard) or already terminal — never override.
            job.setUpdatedAt(System.currentTimeMillis());
            return;
        }
        List<Map<String, Object>> stages = parseStages(job.getStagesJson());
        for (Map<String, Object> stage : stages) {
            if (stageId != null && stageId.equals(stage.get("id"))) {
                stage.put("status", STATUS_WARNING);
            }
        }
        job.setStagesJson(writeStages(stages));
        job.setState(STATE_COMPLETED_WITH_WARNINGS);
        job.setCurrentStageId(null);
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("stageId", stageId);
        err.put("message", message);
        try {
            job.setErrorJson(MAPPER.writeValueAsString(err));
        } catch (Exception ser) {
            job.setErrorJson("{\"stageId\":null,\"message\":\"<unserializable>\"}");
        }
        job.setUpdatedAt(System.currentTimeMillis());
    }

    static void applyFail(IgaToggleJobEntity job, String stageId, String message) {
        List<Map<String, Object>> stages = parseStages(job.getStagesJson());
        for (Map<String, Object> stage : stages) {
            if (stageId != null && stageId.equals(stage.get("id"))) {
                stage.put("status", STATUS_FAILED);
            }
        }
        job.setStagesJson(writeStages(stages));
        job.setState(STATE_FAILED);
        job.setCurrentStageId(stageId);
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("stageId", stageId);
        err.put("message", message);
        try {
            job.setErrorJson(MAPPER.writeValueAsString(err));
        } catch (Exception ser) {
            job.setErrorJson("{\"stageId\":null,\"message\":\"<unserializable>\"}");
        }
        job.setUpdatedAt(System.currentTimeMillis());
    }

    /**
     * Apply {@code mutator} to the matching stage map within the entity's
     * serialized stages, then set the job {@code currentStageId} (only while the
     * job is still {@code running}) and bump {@code UPDATED_AT}. A failed/completed
     * job's state/currentStageId is left untouched.
     */
    private static void mutateStageEntity(IgaToggleJobEntity job, String stageId,
                                          String currentStageId,
                                          java.util.function.Consumer<Map<String, Object>> mutator) {
        List<Map<String, Object>> stages = parseStages(job.getStagesJson());
        boolean found = false;
        for (Map<String, Object> stage : stages) {
            if (stageId != null && stageId.equals(stage.get("id"))) {
                mutator.accept(stage);
                found = true;
                break;
            }
        }
        if (!found) {
            log.debugf("IGA toggle-job %s: stage '%s' not found (ignored)", job.getJobId(), stageId);
        }
        job.setStagesJson(writeStages(stages));
        if (STATE_RUNNING.equals(job.getState())) {
            job.setCurrentStageId(currentStageId);
        }
        job.setUpdatedAt(System.currentTimeMillis());
    }

    /**
     * Read the job row and assemble the locked-contract status JSON. Returns
     * {@code null} if the jobId is unknown (caller maps to 404).
     */
    public Map<String, Object> getStatus(KeycloakSession session, String jobId) {
        if (jobId == null) return null;
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaToggleJobEntity job = em.find(IgaToggleJobEntity.class, jobId);
        if (job == null) return null;
        return toStatusMap(job);
    }

    /** Serialize a {@link IgaToggleJobEntity} row into the contract status map. */
    public static Map<String, Object> toStatusMap(IgaToggleJobEntity job) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jobId", job.getJobId());
        out.put("state", job.getState());
        out.put("currentStageId", job.getCurrentStageId());
        out.put("stages", parseStagesStatic(job.getStagesJson()));
        out.put("error", parseError(job.getErrorJson()));
        return out;
    }

    // ---- internals ----------------------------------------------------------

    private void runInTx(java.util.function.Consumer<EntityManager> work) {
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, s -> {
                EntityManager em = s.getProvider(JpaConnectionProvider.class).getEntityManager();
                work.accept(em);
            });
        } catch (RuntimeException ex) {
            // Best-effort: a progress write must never abort/observe-fail the toggle.
            log.warnf(ex, "IGA toggle-job: progress write failed (best-effort, continuing)");
        }
    }

    private static String serializeStages(List<Stage> stages) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stages != null) {
            for (Stage s : stages) list.add(s.toMap());
        }
        return writeStages(list);
    }

    private static String writeStages(List<Map<String, Object>> stages) {
        try {
            return MAPPER.writeValueAsString(stages);
        } catch (Exception ser) {
            return "[]";
        }
    }

    private static List<Map<String, Object>> parseStages(String json) {
        return parseStagesStatic(json);
    }

    private static List<Map<String, Object>> parseStagesStatic(String json) {
        if (json == null || json.isBlank()) return new ArrayList<>();
        try {
            List<Map<String, Object>> parsed = MAPPER.readValue(json, STAGES_REF);
            return parsed != null ? parsed : new ArrayList<>();
        } catch (Exception parse) {
            return new ArrayList<>();
        }
    }

    private static Map<String, Object> parseError(String json) {
        if (json == null || json.isBlank()) return null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = MAPPER.readValue(json, Map.class);
            return m;
        } catch (Exception parse) {
            return null;
        }
    }
}
