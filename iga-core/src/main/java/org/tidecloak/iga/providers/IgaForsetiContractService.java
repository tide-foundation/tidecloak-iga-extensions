package org.tidecloak.iga.providers;

import org.tidecloak.iga.entities.IgaForsetiContractEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing the realm-scoped library of policy contract source
 * code (Rego or similar). Contracts are deduplicated within a realm by SHA-256
 * hash of {@code contractCode}.
 */
public class IgaForsetiContractService {

    private final EntityManager em;

    public IgaForsetiContractService(EntityManager em) {
        this.em = em;
    }

    /**
     * Insert or update a contract for {@code realmId}. Lookup is by
     * (realmId, sha256(contractCode)). If an existing contract is found, only
     * {@code name} and {@code updatedAt} are touched (the body is immutable
     * because it defines the hash). Otherwise a new row is inserted with a
     * generated UUID and {@code createdAt}.
     */
    public IgaForsetiContractEntity upsert(String realmId, String contractCode, String name) {
        String hash = sha256Hex(contractCode);
        IgaForsetiContractEntity existing = findByRealmAndHash(realmId, hash);
        long now = System.currentTimeMillis();
        if (existing != null) {
            existing.setName(name);
            existing.setUpdatedAt(now);
            em.merge(existing);
            em.flush();
            return existing;
        }

        IgaForsetiContractEntity entity = new IgaForsetiContractEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realmId);
        entity.setContractHash(hash);
        entity.setContractCode(contractCode);
        entity.setName(name);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Find a contract by id. Returns null if not found.
     */
    public IgaForsetiContractEntity findById(String id) {
        return em.find(IgaForsetiContractEntity.class, id);
    }

    /**
     * Find a contract by (realmId, contractHash). Returns null if not found.
     */
    public IgaForsetiContractEntity findByRealmAndHash(String realmId, String hash) {
        TypedQuery<IgaForsetiContractEntity> query = em.createNamedQuery(
                "IgaForsetiContract.findByRealmAndHash", IgaForsetiContractEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("hash", hash);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    /**
     * List all contracts for a realm, ordered by createdAt DESC.
     */
    public List<IgaForsetiContractEntity> listByRealm(String realmId) {
        TypedQuery<IgaForsetiContractEntity> query = em.createNamedQuery(
                "IgaForsetiContract.findByRealm", IgaForsetiContractEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * Delete a contract by id. No-op if it doesn't exist. Any IGA_ROLE_POLICY
     * rows that reference this contract will have their CONTRACT_ID nulled by
     * the FK constraint (ON DELETE SET NULL).
     */
    public void deleteById(String id) {
        IgaForsetiContractEntity existing = em.find(IgaForsetiContractEntity.class, id);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
