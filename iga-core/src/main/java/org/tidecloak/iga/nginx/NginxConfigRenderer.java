package org.tidecloak.iga.nginx;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Renders a complete private nginx configuration generation.
 *
 * <pre>
 * &lt;runtime&gt;/config-generations/&lt;generation&gt;/
 *     00-generation.conf   defines $tidecloak_generation, which the :9080 endpoint reports back
 *     10-realms.conf       one server block per private realm
 *     manifest.json        which crypto generations this config references, for cleanup
 * </pre>
 *
 * <p>A generation directory is immutable and complete: nginx includes the whole directory, so a
 * config that named a realm whose material had not been written would fail to load and take every
 * other realm with it.
 */
public final class NginxConfigRenderer {

    /** Without a suffix there are no private endpoints, so nothing is rendered. */
    private static final String DOMAIN_SUFFIX_ENV = "TIDECLOAK_PRIVATE_DOMAIN_SUFFIX";

    /** A single DNS label: what a realm name is allowed to become. */
    private static final Pattern DNS_LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

    private static final Pattern DOMAIN_SUFFIX = Pattern.compile("[a-z0-9.-]{1,253}");

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final Logger log = Logger.getLogger(NginxConfigRenderer.class);

    private NginxConfigRenderer() {
    }

    /**
     * Whether this deployment has private endpoints at all.
     *
     * <p>False means no embedded nginx to talk to — a plain Keycloak image, or the bundle image with
     * its entrypoint overridden — so the whole subsystem stays out of the way instead of failing its
     * way through a reconcile every half hour.
     */
    public static boolean isPrivateTlsConfigured() {
        return domainSuffix() != null;
    }

    /** One realm's private endpoint, resolved to everything the config needs to name it. */
    public record RealmBlock(String realmId, String hostname, long cryptoGeneration) {
    }

    /**
     * The realm's private hostname, or null if it cannot have one.
     *
     * <p>Validated, never sanitised. Rewriting an invalid name into a legal one lets two realms
     * collapse onto one hostname — {@code my_realm} and {@code my-realm} both becoming
     * {@code my-realm} — and nginx resolves a duplicate {@code server_name} by silently serving the
     * first, which would hand one realm's clients the other realm's endpoint. Refusing is the only
     * safe answer.
     */
    public static String privateHostname(RealmModel realm) {
        String suffix = domainSuffix();
        if (suffix == null) {
            return null;
        }
        String label = realm.getName().toLowerCase();
        if (!DNS_LABEL.matcher(label).matches()) {
            log.warnf("Realm '%s' has no private endpoint: its name is not a valid DNS label.",
                    realm.getName());
            return null;
        }
        return label + "." + suffix;
    }

    /**
     * Write the generation, unless this replica already has it.
     *
     * @return the directory holding the rendered config
     */
    public static Path render(long generation, List<RealmBlock> realms) {
        Path target = NginxRuntimeClient.runtimeDir()
                .resolve("config-generations")
                .resolve(Long.toString(generation));
        if (Files.isDirectory(target)) {
            return target;
        }
        try {
            write(target, generation, realms);
        } catch (IOException e) {
            throw new IllegalStateException("Could not render nginx generation " + generation
                    + " at " + target, e);
        }
        log.infof("Rendered nginx generation %d with %d private realm(s) at %s.",
                generation, realms.size(), target);
        return target;
    }

    /** Built aside and renamed in, so nginx can never include a half-written generation. */
    private static void write(Path target, long generation, List<RealmBlock> realms)
            throws IOException {
        Path parent = target.getParent();
        Files.createDirectories(parent);

        Path scratch = parent.resolve(target.getFileName() + ".tmp." + UUID.randomUUID());
        Files.createDirectory(scratch);
        try {
            writeFile(scratch.resolve("00-generation.conf"), generationConf(generation));
            writeFile(scratch.resolve("10-realms.conf"), realmsConf(realms));
            writeFile(scratch.resolve("manifest.json"), manifest(generation, realms));

            Files.move(scratch, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            deleteQuietly(scratch);
            // Another reconcile rendered the same generation first, from the same rows.
            if (Files.isDirectory(target)) {
                return;
            }
            throw e;
        }
    }

    /**
     * What the {@code :9080} control endpoint reports. It is defined by the config nginx has
     * actually loaded, which is what makes it proof of a completed reload rather than of intent.
     */
    private static String generationConf(long generation) {
        return """
                # Generated by TideCloak. Never hand-edit.
                map $host $tidecloak_generation {
                    default "@GENERATION@";
                }
                """.replace("@GENERATION@", Long.toString(generation));
    }

    private static String realmsConf(List<RealmBlock> realms) {
        StringBuilder out = new StringBuilder("# Generated by TideCloak. Never hand-edit.\n");
        if (realms.isEmpty()) {
            out.append("# No private realms are configured.\n");
        }
        for (RealmBlock realm : realms) {
            out.append('\n').append(serverBlock(realm));
        }
        return out.toString();
    }

    /**
     * The upstream {@code tidecloak_backend} is defined by the image's own http-level config, not
     * here — this file is included into that same {@code http} context.
     */
    private static String serverBlock(RealmBlock realm) {
        String material = NginxRuntimeClient.runtimeDir()
                .resolve("realm-material")
                .resolve(realm.realmId())
                .resolve(Long.toString(realm.cryptoGeneration()))
                .toString();

        return """
                server {
                    listen 8443 ssl;
                    server_name @HOSTNAME@;

                    ssl_certificate     @MATERIAL@/server.crt;
                    ssl_certificate_key @MATERIAL@/server.key;

                    # The realm CA CERTIFICATE only. Its private key is never projected here.
                    ssl_client_certificate @MATERIAL@/ca.pem;
                    ssl_verify_client on;
                    ssl_verify_depth 1;

                    # Stop an SNI of realm A plus an HTTP Host of realm B from switching request
                    # context after the handshake verified against realm A's CA.
                    if ($host != $ssl_server_name) { return 421; }

                    location / {
                        proxy_pass http://tidecloak_backend;
                        proxy_set_header Connection "";

                        # SNI is the authoritative private routing identity.
                        proxy_set_header Host              $ssl_server_name;

                        # No client IP is forwarded on this hop, deliberately. TideCloak tells the
                        # private path from the public one by seeing the immediate peer as loopback,
                        # and a forwarded address would destroy that.
                        proxy_set_header X-Real-IP         "";
                        proxy_set_header X-Forwarded-For   "";
                        proxy_set_header X-Forwarded-Host  $ssl_server_name;
                        proxy_set_header X-Forwarded-Proto https;
                        proxy_set_header X-Forwarded-Port  443;

                        proxy_set_header Forwarded               "";
                        proxy_set_header X-Forwarded-Prefix      "";
                        proxy_set_header X-Forwarded-Ssl         "";
                        proxy_set_header X-Forwarded-Server      "";
                        proxy_set_header X-SSL-Client-Cert       "";
                        proxy_set_header SSL-Client-Cert         "";
                        proxy_set_header X-Forwarded-Client-Cert "";

                        # The only certificate assertion forwarded. TideCloak must accept it only on
                        # the loopback private path, then bind it to the realm/client itself.
                        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
                    }
                }
                """
                .replace("@HOSTNAME@", realm.hostname())
                .replace("@MATERIAL@", material);
    }

    /** Records which crypto generations this config pins, so cleanup knows what is still live. */
    private static String manifest(long generation, List<RealmBlock> realms) throws IOException {
        ObjectNode root = JSON.createObjectNode();
        root.put("proxyGeneration", generation);
        ArrayNode array = root.putArray("realms");
        for (RealmBlock realm : realms) {
            ObjectNode node = array.addObject();
            node.put("realmId", realm.realmId());
            node.put("hostname", realm.hostname());
            node.put("cryptoGeneration", realm.cryptoGeneration());
        }
        return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root) + "\n";
    }

    /** Null when unset or malformed — either way there are no private endpoints. */
    private static String domainSuffix() {
        String suffix = System.getenv(DOMAIN_SUFFIX_ENV);
        if (suffix == null || suffix.isBlank()) {
            return null;
        }
        String trimmed = suffix.trim().toLowerCase();
        if (!DOMAIN_SUFFIX.matcher(trimmed).matches()) {
            log.errorf("%s is not a valid domain suffix: '%s'. No private endpoints will be rendered.",
                    DOMAIN_SUFFIX_ENV, suffix);
            return null;
        }
        return trimmed;
    }

    private static void writeFile(Path path, String body) throws IOException {
        Files.write(path, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void deleteQuietly(Path directory) {
        try (var entries = Files.list(directory)) {
            for (Path entry : entries.toList()) {
                Files.deleteIfExists(entry);
            }
            Files.deleteIfExists(directory);
        } catch (IOException e) {
            log.debugf("Could not clean up %s: %s", directory, e.getMessage());
        }
    }
}
