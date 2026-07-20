package org.tidecloak.iga.producer.units;

/**
 * Single-valued attribute / config / mapper-config entry — the ork
 * {@code NameValue(name,value)} record. Wire shape: {@code {"name","value"}}.
 */
public record NameValue(String name, String value) {
}
