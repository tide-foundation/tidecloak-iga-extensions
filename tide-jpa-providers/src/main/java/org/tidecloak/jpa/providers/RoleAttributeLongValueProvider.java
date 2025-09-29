package org.tidecloak.jpa.providers;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.tidecloak.jpa.entities.RoleAttributeLongEntity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Provider/DAO for ROLE_ATTRIBUTE_LONG using the RoleAttributeLongEntity.
 * Stores large values as gzip + base64url in CLOB to bypass 255-char limit.
 */
public final class RoleAttributeLongValueProvider {

    private RoleAttributeLongValueProvider() {}

    /** Returns the RAW (decompressed) value for (roleId,name) or null if not present. */
    public static String getRaw(KeycloakSession session, String roleId, String name) {
        RoleAttributeLongEntity e = find(session, roleId, name);
        if (e == null) return null;
        return decodeGzipBase64Url(e.getValue());
    }

    /** Upserts RAW (uncompressed) value. Passing null deletes the row. */
    public static void putRaw(KeycloakSession session, String roleId, String name, String rawValue) {
        if (rawValue == null) {
            delete(session, roleId, name);
            return;
        }

        String encoded = encodeGzipBase64Url(rawValue);
        String hash = sha256Hex(rawValue);

        EntityManager em = em(session);
        RoleAttributeLongEntity existing = find(session, roleId, name);

        if (existing == null) {
            RoleAttributeLongEntity e = new RoleAttributeLongEntity();
            e.setId(UUID.randomUUID().toString());
            e.setRoleId(roleId);
            e.setName(name);
            e.setValue(encoded);
            e.setHashSha256(hash);
            long now = System.currentTimeMillis();
            e.setCreatedAt(now);
            e.setUpdatedAt(now);
            em.persist(e);
        } else {
            existing.setValue(encoded);
            existing.setHashSha256(hash);
            existing.setUpdatedAt(System.currentTimeMillis());
            em.merge(existing);
        }
        em.flush();
    }

    /** Deletes the attribute if it exists. */
    public static void delete(KeycloakSession session, String roleId, String name) {
        em(session).createNamedQuery("RoleAttributeLongEntity.deleteByRoleAndName")
                .setParameter("roleId", roleId)
                .setParameter("name", name)
                .executeUpdate();
        em(session).flush();
    }

    /** Returns SHA-256 hex of RAW value if present, else null. */
    public static String getRawHash(KeycloakSession session, String roleId, String name) {
        RoleAttributeLongEntity e = find(session, roleId, name);
        return (e == null) ? null : e.getHashSha256();
    }

    /* --------------------- internals --------------------- */

    private static RoleAttributeLongEntity find(KeycloakSession session, String roleId, String name) {
        try {
            return em(session).createNamedQuery("RoleAttributeLongEntity.getByRoleAndName", RoleAttributeLongEntity.class)
                    .setParameter("roleId", roleId)
                    .setParameter("name", name)
                    .getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    private static EntityManager em(KeycloakSession session) {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    /* --------------------- codec helpers --------------------- */

    private static String encodeGzipBase64Url(String raw) {
        try {
            byte[] input = raw.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
                gos.write(input);
            }
            byte[] gz = baos.toByteArray();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(gz);
        } catch (Exception e) {
            throw new RuntimeException("Failed to gzip+base64url encode", e);
        }
    }

    private static String decodeGzipBase64Url(String encoded) {
        try {
            byte[] gz = Base64.getUrlDecoder().decode(encoded);
            try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int r;
                while ((r = gis.read(buf)) != -1) {
                    baos.write(buf, 0, r);
                }
                return baos.toString(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to base64url+gunzip decode", e);
        }
    }

    private static String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(h.length * 2);
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute SHA-256", e);
        }
    }
}
