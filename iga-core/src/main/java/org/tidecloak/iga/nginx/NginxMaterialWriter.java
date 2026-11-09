package org.tidecloak.iga.nginx;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaRealmCertEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaRealmCertService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Projects a realm's issued certificates onto this replica's disk for nginx to read.
 *
 * <p>Local and disposable. The database stays authoritative — everything written here can be
 * rebuilt from it, which is what lets a new replica join without copying files from a peer.
 *
 * <pre>
 * &lt;runtime&gt;/realm-material/&lt;realmId&gt;/&lt;cryptoGeneration&gt;/
 *     ca.pem       realm root CA — what nginx verifies client certificates against
 *     server.crt   realm server certificate — what nginx presents
 *     server.key   its private key
 * </pre>
 *
 * <p>A crypto generation directory is immutable. Nothing is ever written into one that already
 * exists, so nginx cannot read a file that is being rewritten underneath it, and a config still
 * referencing an older generation keeps working.
 *
 * <p>The CA private key is never written here. nginx has no use for it and the issuing key is a
 * threshold key Tidecloak does not hold in the first place.
 */
public final class NginxMaterialWriter {

    private static final Set<PosixFilePermission> DIR_PERMISSIONS =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> KEY_PERMISSIONS =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> CERT_PERMISSIONS =
            PosixFilePermissions.fromString("rw-r--r--");

    private static final Logger log = Logger.getLogger(NginxMaterialWriter.class);

    private NginxMaterialWriter() {
    }

    /** What was written, and where nginx should point at it. */
    public record Material(String realmId, long cryptoGeneration, Path directory) {
    }

    /**
     * Write the realm's current certificates, unless this replica already has them.
     *
     * @return what is on disk, or null if the realm has no issued certificate yet
     */
    public static Material materializeRealm(KeycloakSession session, RealmModel realm, EntityManager em) {
        IgaRealmCertService service = new IgaRealmCertService(em, new IgaChangeRequestService(em, session));
        IgaRealmCertEntity current = service.findCurrent(realm.getId());
        if (current == null || current.getServerCertificate() == null
                || current.getRootCaCertificate() == null) {
            return null;
        }

        long generation = cryptoGenerationOf(service, realm.getId(), current);
        Path target = NginxRuntimeClient.runtimeDir()
                .resolve("realm-material")
                .resolve(realm.getId())
                .resolve(Long.toString(generation));

        if (Files.isDirectory(target)) {
            return new Material(realm.getId(), generation, target);
        }

        String privateKeyPem = resolveServerPrivateKeyPem(session, realm, current);
        try {
            write(target, current, privateKeyPem);
        } catch (IOException e) {
            throw new IllegalStateException("Could not materialize certificates for realm "
                    + realm.getName() + " at " + target, e);
        }
        log.infof("Materialized realm %s crypto generation %d at %s.",
                realm.getName(), generation, target);
        return new Material(realm.getId(), generation, target);
    }

    /**
     * Build the whole generation in a scratch directory and rename it into place, so a crash or a
     * failure part-way through cannot leave nginx a directory holding two of the three files.
     * The rename is atomic and refuses to clobber, which also settles the race between two
     * reconciles arriving at once — the loser sees the winner's directory and moves on.
     */
    private static void write(Path target, IgaRealmCertEntity cert, String privateKeyPem)
            throws IOException {
        Path parent = target.getParent();
        Files.createDirectories(parent);
        applyPermissions(parent, DIR_PERMISSIONS);

        Path scratch = parent.resolve(target.getFileName() + ".tmp." + UUID.randomUUID());
        Files.createDirectory(scratch);
        applyPermissions(scratch, DIR_PERMISSIONS);
        try {
            writeFile(scratch.resolve("ca.pem"), cert.getRootCaCertificate(), CERT_PERMISSIONS);
            writeFile(scratch.resolve("server.crt"), cert.getServerCertificate(), CERT_PERMISSIONS);
            writeFile(scratch.resolve("server.key"), privateKeyPem, KEY_PERMISSIONS);

            Files.move(scratch, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            deleteQuietly(scratch);
            // Another reconcile finished first. Its directory holds the same bytes.
            if (Files.isDirectory(target)) {
                return;
            }
            throw e;
        }
    }

    private static void writeFile(Path path, String pem, Set<PosixFilePermission> permissions)
            throws IOException {
        String body = pem.endsWith("\n") ? pem : pem + "\n";
        Files.write(path, body.getBytes(StandardCharsets.UTF_8));
        applyPermissions(path, permissions);
    }

    /**
     * The private key half of the certificate's subject key.
     *
     * <p>Matched against the SubjectPublicKeyInfo stored on the row rather than taking the realm's
     * currently active ES256 key: once that key rotates, the active one no longer belongs to this
     * certificate, and writing it would hand nginx a key and certificate that do not agree. No
     * match means the key is gone, which is a failure rather than something to paper over.
     */
    private static String resolveServerPrivateKeyPem(KeycloakSession session, RealmModel realm,
                                                     IgaRealmCertEntity cert) {
        byte[] wanted = Base64.getUrlDecoder().decode(cert.getServerPublicKey());
        KeyWrapper match = session.keys()
                .getKeysStream(realm, KeyUse.SIG, Algorithm.ES256)
                .filter(key -> key.getPublicKey() != null
                        && Arrays.equals(key.getPublicKey().getEncoded(), wanted))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Realm " + realm.getName() + " has no key matching the subject public key of "
                                + "its server certificate; the keypair it was issued for is gone."));

        Key privateKey = match.getPrivateKey();
        if (privateKey == null || privateKey.getEncoded() == null) {
            throw new IllegalStateException("Realm " + realm.getName()
                    + " server certificate key is not exportable.");
        }
        return pem("PRIVATE KEY", privateKey.getEncoded());
    }

    private static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    /**
     * Which issuance this row is for the realm, counting from 1.
     *
     * <p>Derived rather than stored, so it depends on the row set being append-only — every replica
     * reads the same rows and computes the same number, which is what makes the path agree across
     * the cluster. A persisted column would be sturdier if issuance rows ever start being purged.
     */
    private static long cryptoGenerationOf(IgaRealmCertService service, String realmId,
                                           IgaRealmCertEntity row) {
        List<IgaRealmCertEntity> issued = service.listByRealm(realmId).stream()
                .filter(candidate -> candidate.getServerCertificate() != null)
                .sorted(Comparator.comparingLong(IgaRealmCertEntity::getCreatedAt))
                .toList();
        long generation = 0;
        for (IgaRealmCertEntity candidate : issued) {
            generation++;
            if (candidate.getId().equals(row.getId())) {
                break;
            }
        }
        return generation;
    }

    /** Skipped on filesystems without POSIX permissions rather than failing the write. */
    private static void applyPermissions(Path path, Set<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (IOException | UnsupportedOperationException e) {
            log.debugf("Could not set permissions on %s: %s", path, e.getMessage());
        }
    }

    private static void deleteQuietly(Path root) {
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException e) throws IOException {
                    Files.deleteIfExists(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.debugf("Could not clean up %s: %s", root, e.getMessage());
        }
    }
}
