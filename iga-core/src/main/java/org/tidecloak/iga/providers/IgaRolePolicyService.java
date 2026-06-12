package org.tidecloak.iga.providers;

import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing realm-level named policy records (Midgard policy bytes /
 * signature combined with Forseti contract binding). Each record is keyed by
 * (realmId, name) — policies are realm-level named records decoupled from any
 * specific role.
 */
public class IgaRolePolicyService {

    private final EntityManager em;

    public IgaRolePolicyService(EntityManager em) {
        this.em = em;
    }

    /**
     * Insert or update a realm-level policy. Lookup is by (realmId, name).
     * If an existing record is found, all fields are overwritten and updatedAt is set.
     * Otherwise a new row is inserted with a generated UUID id and createdAt set.
     */
    public IgaRolePolicyEntity upsert(String realmId, String name, String policy,
                                      String policySig, String contractId,
                                      String approvalType, String executionType,
                                      Integer threshold, String policyData) {
        IgaRolePolicyEntity existing = findByRealmAndName(realmId, name);
        long now = System.currentTimeMillis();
        if (existing != null) {
            existing.setPolicy(policy);
            existing.setPolicySig(policySig);
            existing.setContractId(contractId);
            existing.setApprovalType(approvalType);
            existing.setExecutionType(executionType);
            existing.setThreshold(threshold);
            existing.setPolicyData(policyData);
            existing.setUpdatedAt(now);
            em.merge(existing);
            em.flush();
            return existing;
        }

        IgaRolePolicyEntity entity = new IgaRolePolicyEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realmId);
        entity.setName(name);
        entity.setPolicy(policy);
        entity.setPolicySig(policySig);
        entity.setContractId(contractId);
        entity.setApprovalType(approvalType);
        entity.setExecutionType(executionType);
        entity.setThreshold(threshold);
        entity.setPolicyData(policyData);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Find a policy by (realmId, name). Returns null if not found.
     */
    public IgaRolePolicyEntity findByRealmAndName(String realmId, String name) {
        TypedQuery<IgaRolePolicyEntity> query = em.createNamedQuery(
                "IgaRolePolicy.findByRealmAndName", IgaRolePolicyEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("name", name);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    /**
     * Find a policy by id. Returns null if not found.
     */
    public IgaRolePolicyEntity findById(String id) {
        return em.find(IgaRolePolicyEntity.class, id);
    }

    /**
     * List all policies for a realm, ordered by createdAt DESC.
     */
    public List<IgaRolePolicyEntity> listByRealm(String realmId) {
        TypedQuery<IgaRolePolicyEntity> query = em.createNamedQuery(
                "IgaRolePolicy.findByRealm", IgaRolePolicyEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * Delete a policy by (realmId, name). No-op if it doesn't exist.
     */
    public void deleteByRealmAndName(String realmId, String name) {
        IgaRolePolicyEntity existing = findByRealmAndName(realmId, name);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }

    /**
     * Delete a policy by id. No-op if it doesn't exist.
     */
    public void deleteById(String id) {
        IgaRolePolicyEntity existing = em.find(IgaRolePolicyEntity.class, id);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }
}
