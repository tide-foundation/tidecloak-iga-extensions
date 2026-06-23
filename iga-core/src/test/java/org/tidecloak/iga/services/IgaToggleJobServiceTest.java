package org.tidecloak.iga.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.tidecloak.iga.entities.IgaToggleJobEntity;

/**
 * Unit tests for {@link IgaToggleJobService} — the DB-free entity transitions
 * (the source of truth the tx mutators delegate to) and the locked-contract
 * status serialization shape.
 */
class IgaToggleJobServiceTest {

    private static String STAGES_JSON() {
        return serialize(
                new IgaToggleJobService.Stage("setup-realm", "Setting up realm"),
                new IgaToggleJobService.Stage("adopt-scan", "Adopting existing configuration"),
                new IgaToggleJobService.Stage("sign-defaults", "Signing default roles & config"),
                new IgaToggleJobService.Stage("finalize", "Finalizing"));
    }

    private static String serialize(IgaToggleJobService.Stage... s) {
        // Reuse the production serializer via a fresh-started entity.
        IgaToggleJobEntity job = new IgaToggleJobEntity();
        job.setJobId("seed");
        job.setCreatedAt(0L);
        // applyStart needs a pre-serialized stages json, so do it the long way:
        // build via the public stages() + the same Jackson path applyStart uses.
        // Simplest: start a real service-less entity by serializing each stage map.
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < s.length; i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"id\":\"").append(s[i].id).append("\",\"label\":\"")
              .append(s[i].label).append("\",\"status\":\"pending\",\"current\":null,\"total\":null}");
        }
        sb.append("]");
        return sb.toString();
    }

    private static IgaToggleJobEntity freshJob() {
        IgaToggleJobEntity job = new IgaToggleJobEntity();
        job.setJobId("job-1");
        job.setCreatedAt(1000L);
        IgaToggleJobService.applyStart(job, "realm-1", STAGES_JSON(), 1000L);
        return job;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> stagesOf(IgaToggleJobEntity job) {
        return (List<Map<String, Object>>) IgaToggleJobService.toStatusMap(job).get("stages");
    }

    private static Map<String, Object> stage(IgaToggleJobEntity job, String id) {
        for (Map<String, Object> s : stagesOf(job)) {
            if (id.equals(s.get("id"))) return s;
        }
        return null;
    }

    @Test
    void start_initializesAllStagesPending_stateRunning() {
        IgaToggleJobEntity job = freshJob();
        Map<String, Object> status = IgaToggleJobService.toStatusMap(job);

        assertEquals("job-1", status.get("jobId"));
        assertEquals(IgaToggleJobService.STATE_RUNNING, status.get("state"));
        assertNull(status.get("currentStageId"));
        assertNull(status.get("error"));

        List<Map<String, Object>> stages = stagesOf(job);
        assertEquals(4, stages.size());
        for (Map<String, Object> s : stages) {
            assertEquals("pending", s.get("status"));
            assertNotNull(s.get("id"));
            assertNotNull(s.get("label"));
            assertTrue(s.containsKey("current"));
            assertTrue(s.containsKey("total"));
            assertNull(s.get("current"));
            assertNull(s.get("total"));
        }
    }

    @Test
    void stageRunning_marksRunning_andSetsCurrentStage() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyStageRunning(job, "setup-realm", null, null);

        assertEquals("setup-realm", IgaToggleJobService.toStatusMap(job).get("currentStageId"));
        assertEquals("running", stage(job, "setup-realm").get("status"));
        assertEquals("pending", stage(job, "adopt-scan").get("status"));
    }

    @Test
    void stageProgress_updatesCounts_keepsRunning() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyStageRunning(job, "sign-defaults", 0L, 10L);
        IgaToggleJobService.applyStageProgress(job, "sign-defaults", 4L, 10L);

        Map<String, Object> s = stage(job, "sign-defaults");
        assertEquals("running", s.get("status"));
        assertEquals(4, ((Number) s.get("current")).intValue());
        assertEquals(10, ((Number) s.get("total")).intValue());
    }

    @Test
    void stageDone_marksDone_clearsCurrentStage_withCounts() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyStageRunning(job, "adopt-scan", null, null);
        IgaToggleJobService.applyStageDone(job, "adopt-scan", 42L, 42L);

        Map<String, Object> s = stage(job, "adopt-scan");
        assertEquals("done", s.get("status"));
        assertEquals(42, ((Number) s.get("current")).intValue());
        assertEquals(42, ((Number) s.get("total")).intValue());
        assertNull(IgaToggleJobService.toStatusMap(job).get("currentStageId"));
    }

    @Test
    void complete_setsStateCompleted_whenRunning() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyStageRunning(job, "finalize", null, null);
        IgaToggleJobService.applyStageDone(job, "finalize", null, null);
        IgaToggleJobService.applyComplete(job);

        Map<String, Object> status = IgaToggleJobService.toStatusMap(job);
        assertEquals(IgaToggleJobService.STATE_COMPLETED, status.get("state"));
        assertNull(status.get("currentStageId"));
        assertNull(status.get("error"));
    }

    @Test
    void fail_marksStageFailed_jobFailed_populatesError() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyStageRunning(job, "sign-defaults", 0L, 5L);
        IgaToggleJobService.applyFail(job, "sign-defaults", "ORK signing exploded");

        Map<String, Object> status = IgaToggleJobService.toStatusMap(job);
        assertEquals(IgaToggleJobService.STATE_FAILED, status.get("state"));
        assertEquals("sign-defaults", status.get("currentStageId"));
        assertEquals("failed", stage(job, "sign-defaults").get("status"));

        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) status.get("error");
        assertNotNull(error);
        assertEquals("sign-defaults", error.get("stageId"));
        assertEquals("ORK signing exploded", error.get("message"));
    }

    @Test
    void complete_doesNotResurrectFailedJob() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyFail(job, "adopt-scan", "boom");
        // A subsequent complete() must NOT flip a failed job back to completed.
        IgaToggleJobService.applyComplete(job);

        assertEquals(IgaToggleJobService.STATE_FAILED,
                IgaToggleJobService.toStatusMap(job).get("state"));
    }

    @Test
    void stageProgress_doesNotResurrectFailedStage() {
        IgaToggleJobEntity job = freshJob();
        IgaToggleJobService.applyFail(job, "sign-defaults", "boom");
        // A late progress callback after a failure must not flip the stage back to running.
        IgaToggleJobService.applyStageProgress(job, "sign-defaults", 9L, 10L);

        assertEquals("failed", stage(job, "sign-defaults").get("status"));
    }

    @Test
    void statusShape_matchesLockedContract_keysPresent() {
        IgaToggleJobEntity job = freshJob();
        Map<String, Object> status = IgaToggleJobService.toStatusMap(job);

        // Locked contract: jobId, state, currentStageId, stages[], error.
        assertTrue(status.containsKey("jobId"));
        assertTrue(status.containsKey("state"));
        assertTrue(status.containsKey("currentStageId"));
        assertTrue(status.containsKey("stages"));
        assertTrue(status.containsKey("error"));

        // Each stage carries id, label, status, current, total.
        for (Map<String, Object> s : stagesOf(job)) {
            assertTrue(s.containsKey("id"));
            assertTrue(s.containsKey("label"));
            assertTrue(s.containsKey("status"));
            assertTrue(s.containsKey("current"));
            assertTrue(s.containsKey("total"));
        }
    }

    @Test
    void unknownStageId_isIgnored_noThrow() {
        IgaToggleJobEntity job = freshJob();
        // Must not throw and must not corrupt the stages array.
        IgaToggleJobService.applyStageRunning(job, "no-such-stage", 1L, 2L);
        assertEquals(4, stagesOf(job).size());
    }
}
