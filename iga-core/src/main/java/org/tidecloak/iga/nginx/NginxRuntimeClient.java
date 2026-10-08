package org.tidecloak.iga.nginx;

import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Talks to this replica's own embedded nginx.
 *
 * <p>Two jobs, both delegated to what the container image already provides: ask the running nginx
 * which generation it is serving, and hand a generation to the image's reload helper. Nothing here
 * validates, symlinks or reloads by itself — the helper does all of that as one sequence, and
 * splitting it in Java would mean maintaining a second copy of the activation protocol.
 */
public final class NginxRuntimeClient {

    /**
     * Loopback-only control endpoint. Returns {@code $tidecloak_generation}, which is defined by the
     * {@code 00-generation.conf} inside whichever generation directory is currently active.
     */
    static final String GENERATION_URL = "http://127.0.0.1:9080/_tidecloak/nginx-generation";

    private static final int HTTP_TIMEOUT_MILLIS = 2_000;

    /**
     * Runtime state root. Same variable the container's helper scripts read, so Java and the shell
     * cannot end up pointed at different directories.
     */
    private static final String ROOT_ENV = "TIDECLOAK_NGINX_ROOT";
    private static final String DEFAULT_ROOT = "/run/tidecloak-nginx";

    /** Fixed path, as the image installs it. Never built from anything a realm controls. */
    private static final String RELOAD_SCRIPT_ENV = "TIDECLOAK_NGINX_RELOAD_SCRIPT";
    private static final String DEFAULT_RELOAD_SCRIPT = "/opt/tidecloak/bin/tidecloak-nginx-reload.sh";

    private static final long RELOAD_TIMEOUT_SECONDS = 30;

    /** SIGHUP is asynchronous: the master spawns new workers after the call returns. */
    private static final long ACK_TIMEOUT_MILLIS = 10_000;
    private static final long ACK_POLL_MILLIS = 200;

    private static final Logger log = Logger.getLogger(NginxRuntimeClient.class);

    private NginxRuntimeClient() {
    }

    /** {@code /run/tidecloak-nginx} unless the deployment moved it. */
    static Path runtimeDir() {
        String configured = System.getenv(ROOT_ENV);
        return Path.of(configured == null || configured.isBlank() ? DEFAULT_ROOT : configured);
    }

    /**
     * Validate, activate and reload a generation, then require nginx to confirm it.
     *
     * <p>The helper does the whole sequence: point {@code candidate} at the generation, {@code nginx
     * -t} against the test config, swap {@code active}, {@code nginx -t} against the production
     * config, and SIGHUP the master — rolling {@code active} back itself if the production test
     * fails. A failure at any point therefore leaves this replica on the generation it already had.
     *
     * <p>A zero exit only proves the signal was delivered, so it is not treated as success. nginx
     * has to report the new generation on a fresh connection before this returns true.
     */
    public static boolean activate(long generation) {
        int exit = runReloadScript(generation);
        if (exit != 0) {
            log.errorf("%s %d failed: %s", reloadScript(), generation, explain(exit));
            return false;
        }
        if (!awaitGeneration(generation)) {
            log.errorf("nginx accepted the reload for generation %d but never reported serving it. "
                    + "Treating the activation as failed.", generation);
            return false;
        }
        return true;
    }

    /**
     * The generation nginx is currently serving, or {@link NginxGlobalCounterService#UNAPPLIED_GENERATION}
     * if that cannot be established — nginx down, no active config yet, or an unparseable answer.
     * Unknown counts as behind, so an unreachable nginx gets reconciled rather than assumed healthy.
     *
     * <p>Sends {@code Connection: close} so the socket is never pooled. A reused keep-alive
     * connection can be held by an old worker draining after a reload, which would report the
     * generation that was just replaced.
     */
    public static long readAppliedGeneration() {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) URI.create(GENERATION_URL).toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Connection", "close");
            connection.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
            connection.setReadTimeout(HTTP_TIMEOUT_MILLIS);

            int status = connection.getResponseCode();
            if (status != 200) {
                log.warnf("nginx generation endpoint returned HTTP %d.", status);
                return NginxGlobalCounterService.UNAPPLIED_GENERATION;
            }

            String body;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                body = reader.readLine();
            }
            return parse(body);
        } catch (Exception e) {
            log.warnf(e, "Could not read the nginx generation from %s.", GENERATION_URL);
            return NginxGlobalCounterService.UNAPPLIED_GENERATION;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** Poll until nginx reports the generation, or give up. */
    private static boolean awaitGeneration(long generation) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ACK_TIMEOUT_MILLIS);
        while (true) {
            if (readAppliedGeneration() == generation) {
                return true;
            }
            if (System.nanoTime() >= deadline) {
                return false;
            }
            try {
                Thread.sleep(ACK_POLL_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /**
     * Fixed argument list, no shell. {@code bash -c} would make every string here a potential
     * injection point. The generation is the only variable and it is a {@code long}; the helper
     * re-checks it against {@code ^[0-9]+$} before touching anything.
     *
     * @return the helper's exit code, or -1 if it could not be run at all
     */
    private static int runReloadScript(long generation) {
        List<String> command = List.of(reloadScript(), Long.toString(generation));
        Process process = null;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();

            // Waited on before the output is drained. Safe only because the helper writes a few
            // lines at most, far below the pipe buffer, so it cannot block waiting for a reader.
            if (!process.waitFor(RELOAD_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                log.errorf("%s timed out after %d seconds.", command.get(0), RELOAD_TIMEOUT_SECONDS);
                return -1;
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                    .strip();
            if (!output.isEmpty()) {
                // nginx names the offending file and line here; it is the only useful diagnostic.
                log.infof("%s output:%n%s", command.get(0), output);
            }
            return process.exitValue();
        } catch (IOException e) {
            log.errorf(e, "Could not run %s. Private TLS cannot be reconciled on this replica.",
                    command.get(0));
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    /** The helper's documented exit codes, so a failure reads as a cause rather than a number. */
    private static String explain(int exit) {
        return switch (exit) {
            case -1 -> "the helper could not be run";
            case 64 -> "the generation argument was rejected";
            case 66 -> "the generation directory is missing or incomplete";
            case 69 -> "nginx is not running, or its pid file is unusable";
            case 78 -> "the production config failed validation; the helper rolled the active "
                    + "generation back";
            default -> "the candidate config failed validation (exit " + exit + ")";
        };
    }

    /**
     * Blank is expected, not an error: before the first activation there is no active config, so
     * {@code $tidecloak_generation} is undefined and nginx renders it as an empty string.
     */
    private static long parse(String body) {
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.isEmpty()) {
            return NginxGlobalCounterService.UNAPPLIED_GENERATION;
        }
        try {
            return Long.parseLong(trimmed);
        } catch (NumberFormatException e) {
            log.warnf("nginx generation endpoint returned an unparseable value: '%s'.", trimmed);
            return NginxGlobalCounterService.UNAPPLIED_GENERATION;
        }
    }

    private static String reloadScript() {
        String value = System.getenv(RELOAD_SCRIPT_ENV);
        return value == null || value.isBlank() ? DEFAULT_RELOAD_SCRIPT : value;
    }
}
