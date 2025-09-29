package org.tidecloak.jpa.store;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
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
 * DAO / service for ROLE_ATTRIBUTE_LONG:
 * - Stores large values as gzip+base64url in CLOB
 * - Computes SHA-256 of RAW value for integrity
 * - Upsert by (roleId, name)
 *
 * Also exposes convenience instance methods used by higher layers:
 *  - load/save/remove(session, role, name, ...)
 *  - upsertMirrorShortIfFits(role, name, value) to mirror into ROLE_ATTRIBUTE only if <= 255 chars.
 */
public final class RoleAttributeLongStore {

    /** Public ctor for code that instantiates this as a small helper. */
    public RoleAttributeLongStore() {}

    /* ======================= Instance convenience API ======================= */

    /** Load RAW value for a role attribute, preferring the long-store; falls back to short attr if present. */
    public String load(KeycloakSession session, RoleModel role, String name) {
        String v = getRaw(session, role.getId(), name);
        if (v != null) return v;
        // Fallback to short attribute (legacy / when value is short)
        return role.getFirstAttribute(name);
    }

    /** Save RAW value for a role attribute into the long-store. Does NOT auto-mirror short attr. */
    public void save(KeycloakSession session, RoleModel role, String name, String rawValue) {
        putRaw(session, role.getId(), name, rawValue);
    }

    /** Remove from long-store and clear the short attribute mirror. */
    public void remove(KeycloakSession session, RoleModel role, String name) {
        delete(session, role.getId(), name);
        role.removeAttribute(name);
    }

    /**
     * Mirror into ROLE_ATTRIBUTE only if value length <= 255 (DB column VARCHAR(255)).
     * If longer (or null), removes the short attribute to avoid DB errors and relies on long-store only.
     */
    public void upsertMirrorShortIfFits(RoleModel role, String name, String rawValue) {
        if (rawValue == null) {
            role.removeAttribute(name);
            return;
        }
        if (rawValue.length() <= 255) {
            role.setSingleAttribute(name, rawValue);
        } else {
            // Ensure we don't attempt to store oversized data in ROLE_ATTRIBUTE
            role.removeAttribute(name);
        }
    }

    /* ======================= Static DAO (table access) ======================= */

    /** Get RAW (decompressed) value; returns null if not present. */
    public static String getRaw(KeycloakSession session, String roleId, String name) {
        RoleAttributeLongEntity e = find(session, roleId, name);
        if (e == null) return null;
        return decodeGzipBase64Url(e.getValue());
    }

    /** Upsert RAW (uncompressed) value; passing null deletes the row. */
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

    /** Delete attribute if it exists. */
    public static void delete(KeycloakSession session, String roleId, String name) {
        EntityManager em = em(session);
        em.createNamedQuery("RoleAttributeLongEntity.deleteByRoleAndName")
                .setParameter("roleId", roleId)
                .setParameter("name", name)
                .executeUpdate();
        em.flush();
    }

    /** Returns the SHA-256 hex of the currently stored RAW value, or null if missing. */
    public static String getRawHash(KeycloakSession session, String roleId, String name) {
        RoleAttributeLongEntity e = find(session, roleId, name);
        return (e == null) ? null : e.getHashSha256();
    }

    /* ======================= Internals ======================= */

    private static RoleAttributeLongEntity find(KeycloakSession session, String roleId, String name) {
        EntityManager em = em(session);
        try {
            return em.createNamedQuery("RoleAttributeLongEntity.getByRoleAndName", RoleAttributeLongEntity.class)
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

    /* ======================= Codec ======================= */

    private static String encodeGzipBase64Url(String raw) {
        if (raw == null) return null;
        try {
            byte[] input = raw.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
                gos.write(input);
            }
            byte[] gz = baos.toByteArray();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(gz);
        } catch (Exception e) {
            throw new RuntimeException("Failed to gzip+base64url encode value", e);
        }
    }

    private static String decodeGzipBase64Url(String encoded) {
        if (encoded == null) return null;
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
            throw new RuntimeException("Failed to base64url+gunzip decode value", e);
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
