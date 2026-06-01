package org.tidecloak.iga.producer.units;

import java.util.List;

/**
 * Multi-valued user attribute (unit 7) — the ork {@code NameValues(name,values[])}
 * record. Wire shape: {@code {"name","values":[..]}}.
 */
public record NameValues(String name, List<String> values) {
}
