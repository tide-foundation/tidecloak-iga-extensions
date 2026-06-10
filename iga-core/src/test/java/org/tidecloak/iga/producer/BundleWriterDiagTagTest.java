package org.tidecloak.iga.producer;

import org.junit.jupiter.api.Test;
import org.tidecloak.iga.producer.units.AttestationUnit;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The token-mint bundle map must carry the diagnostics-export discriminators
 * {@code diag_kind=tve_bundle} and {@code diag_tier=1} at the top level, in
 * addition to the existing {@code realm_id}/{@code schema_version}/{@code request}/
 * {@code token}/{@code units} fields. The offline ORK {@code tve-replay} harness
 * keys on these to route the blob.
 */
class BundleWriterDiagTagTest {

    @Test
    void bundleMapCarriesDiagDiscriminators() {
        ExportRequest req = new ExportRequest(
                "my-client", "user-123", "openid profile",
                TokenType.access, null, false);

        Map<String, Object> bundle = new BundleWriter()
                .buildBundleMap("realm-uuid", req, "header.payload.", List.<AttestationUnit>of());

        // New discriminators.
        assertEquals("tve_bundle", bundle.get("diag_kind"));
        assertEquals(1, bundle.get("diag_tier"));

        // Everything else still present and unchanged.
        assertEquals("realm-uuid", bundle.get("realm_id"));
        assertEquals(AttestationUnit.SCHEMA_VERSION, bundle.get("schema_version"));
        assertTrue(bundle.containsKey("request"));
        assertEquals("header.payload.", bundle.get("token"));
        assertTrue(bundle.get("units") instanceof List);
    }

    @Test
    void diagTagsSurviveSerialization() {
        ExportRequest req = ExportRequest.accessToken("c", "u", null);
        byte[] json = new BundleWriter()
                .write("realm-uuid", req, "h.p.", List.<AttestationUnit>of(), BundleWriter.Format.JSON);
        String s = new String(json, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(s.contains("\"diag_kind\""), "serialized JSON must carry diag_kind");
        assertTrue(s.contains("tve_bundle"));
        assertTrue(s.contains("\"diag_tier\""), "serialized JSON must carry diag_tier");
    }
}
