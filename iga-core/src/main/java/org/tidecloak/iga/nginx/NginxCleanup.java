package org.tidecloak.iga.nginx;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Deletes local nginx projections that nothing references any more.
 *
 * <p>Local only. Everything under the runtime directory is a projection of the database and can be
 * rebuilt; the issued certificates themselves are never touched. Nothing here is authority to
 * delete PKI history.
 *
 * <p>Retains the active and previous generations plus every crypto generation their manifests
 * reference, and refuses to delete anything younger than the safety window — nginx keeps old workers
 * alive while they drain, and those workers still hold the files of the generation they were started
 * with.
 */
public final class NginxCleanup {

    /**
     * Comfortably past nginx's {@code worker_shutdown_timeout 30s}, and long enough to still hold
     * the previous generation's files if an activation has to be rolled back.
     */
    private static final Duration SAFETY_WINDOW = Duration.ofMinutes(10);

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final Logger log = Logger.getLogger(NginxCleanup.class);

    private NginxCleanup() {
    }

    /**
     * @param current  the generation this replica is serving
     * @param previous the one before it, or negative if there has not been one
     */
    public static void clean(long current, long previous) {
        if (current < 0) {
            return;
        }
        Path root = NginxRuntimeClient.runtimeDir();

        Set<Long> retained = new HashSet<>(List.of(current));
        if (previous >= 0) {
            retained.add(previous);
        }
        // Whatever the symlinks point at is in use regardless of what this replica thinks it did —
        // a rolled-back activation can leave them naming a generation we never recorded.
        addSymlinkTarget(retained, root.resolve("active"));
        addSymlinkTarget(retained, root.resolve("candidate"));

        Set<String> referenced = referencedMaterial(root, retained);
        if (referenced == null) {
            log.warn("Skipping nginx cleanup: a retained generation's manifest could not be read, "
                    + "so what it references is unknown.");
            return;
        }

        cleanConfigGenerations(root.resolve("config-generations"), retained);
        cleanRealmMaterial(root.resolve("realm-material"), referenced);
    }

    /**
     * Every {@code realmId/cryptoGeneration} the retained generations name.
     *
     * @return null if that cannot be determined, which must abort the whole sweep — deleting
     *         material a live config points at breaks nginx on its next reload
     */
    private static Set<String> referencedMaterial(Path root, Set<Long> retained) {
        Set<String> referenced = new HashSet<>();
        for (Long generation : retained) {
            Path directory = root.resolve("config-generations").resolve(Long.toString(generation));
            if (!Files.isDirectory(directory)) {
                continue;
            }
            Path manifest = directory.resolve("manifest.json");
            if (!Files.isRegularFile(manifest)) {
                // The bootstrap script's generation 0 has no manifest because it has no realms.
                // Anything else missing one is a config whose references we cannot enumerate.
                if (declaresServers(directory.resolve("10-realms.conf"))) {
                    return null;
                }
                continue;
            }
            try {
                JsonNode realms = JSON.readTree(manifest.toFile()).path("realms");
                for (JsonNode realm : realms) {
                    referenced.add(realm.path("realmId").asText() + "/"
                            + realm.path("cryptoGeneration").asLong());
                }
            } catch (IOException e) {
                log.warnf(e, "Could not read %s.", manifest);
                return null;
            }
        }
        return referenced;
    }

    private static void cleanConfigGenerations(Path directory, Set<Long> retained) {
        for (Path candidate : children(directory)) {
            Long generation = generationOf(candidate);
            if (generation == null || retained.contains(generation)) {
                continue;
            }
            deleteIfSettled(candidate, "config generation");
        }
    }

    private static void cleanRealmMaterial(Path directory, Set<String> referenced) {
        for (Path realm : children(directory)) {
            String realmId = realm.getFileName().toString();
            for (Path generation : children(realm)) {
                if (generationOf(generation) == null) {
                    continue;
                }
                if (referenced.contains(realmId + "/" + generation.getFileName())) {
                    continue;
                }
                deleteIfSettled(generation, "realm material");
            }
            // The realm itself is gone, or has no certificate any more.
            if (children(realm).isEmpty()) {
                deleteIfSettled(realm, "realm material directory");
            }
        }
    }

    /** Deletes only once the directory is older than the safety window. */
    private static void deleteIfSettled(Path directory, String what) {
        try {
            long age = System.currentTimeMillis()
                    - Files.getLastModifiedTime(directory).toMillis();
            if (age < SAFETY_WINDOW.toMillis()) {
                return;
            }
            deleteRecursively(directory);
            log.infof("Removed unreferenced %s %s.", what, directory);
        } catch (IOException e) {
            log.warnf(e, "Could not remove %s.", directory);
        }
    }

    /** True if the file contains a server block, i.e. it names material we would have to keep. */
    private static boolean declaresServers(Path realmsConf) {
        try {
            return Files.isRegularFile(realmsConf)
                    && Files.readString(realmsConf).contains("server {");
        } catch (IOException e) {
            return true;
        }
    }

    private static void addSymlinkTarget(Set<Long> retained, Path link) {
        try {
            if (Files.isSymbolicLink(link)) {
                Long generation = generationOf(Files.readSymbolicLink(link));
                if (generation != null) {
                    retained.add(generation);
                }
            }
        } catch (IOException e) {
            log.debugf("Could not resolve %s: %s", link, e.getMessage());
        }
    }

    /** Null for anything not named after a generation, so scratch directories are left alone. */
    private static Long generationOf(Path directory) {
        try {
            return Long.parseLong(directory.getFileName().toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static List<Path> children(Path directory) {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.filter(Files::isDirectory).toList();
        } catch (IOException e) {
            log.warnf(e, "Could not list %s.", directory);
            return List.of();
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        List<Path> paths = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root)) {
            walk.forEach(paths::add);
        }
        for (int i = paths.size() - 1; i >= 0; i--) {
            Files.deleteIfExists(paths.get(i));
        }
    }
}
