package org.tidecloak.iga.producer.units;

/**
 * Client-scope assignment row (unit 12) — the ork
 * {@code ScopeAssignment(client_scope_id,default)} record.
 * {@code isDefault} maps to the wire key {@code "default"}
 * ({@code default} is a Java keyword, so the accessor is renamed but the
 * emitted key stays {@code "default"}).
 */
public record ScopeAssignment(String clientScopeId, boolean isDefault) {
}
