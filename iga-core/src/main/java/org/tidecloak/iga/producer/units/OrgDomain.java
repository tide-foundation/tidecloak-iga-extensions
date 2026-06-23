package org.tidecloak.iga.producer.units;

/**
 * Verified org email domain (unit 18) — the ork {@code OrgDomain(name,verified)}
 * record. Wire shape: {@code {"name","verified"}}.
 */
public record OrgDomain(String name, boolean verified) {
}
