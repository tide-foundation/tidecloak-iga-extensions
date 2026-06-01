package org.tidecloak.iga.providers;

import org.tidecloak.iga.entities.IgaAuthorizerEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing per-realm authorizer registrations (admin signers).
 */
public class IgaAuthorizerService {

    private final EntityManager em;

    public IgaAuthorizerService(EntityManager em) {
        this.em = em;
    }

    /**
     * Create a new authorizer record. Generates UUID id and sets createdAt.
     *
     * <p>Mode is left at the entity's {@code multiAdmin} default (mirroring the
     * {@code MODE} column {@code defaultValue}); the operator-facing
     * {@code POST /iga/authorizers} path uses this overload. The firstAdmin lazy
     * seed uses {@link #create(String, String, String, String, String, String)}
     * to set {@code mode="firstAdmin"} explicitly (port plan §9.3).
     */
    public IgaAuthorizerEntity create(String realmId, String providerId, String type,
                                       String authorizer, String authorizerCertificate) {
        return create(realmId, providerId, type, authorizer, authorizerCertificate, null);
    }

    /**
     * Create a new authorizer record with an explicit firstAdmin/multiAdmin
     * {@code mode} (port plan §9.3 lazy seed). A {@code null} mode leaves the
     * entity's Java-side {@code multiAdmin} default in place.
     */
    public IgaAuthorizerEntity create(String realmId, String providerId, String type,
                                       String authorizer, String authorizerCertificate, String mode) {
        IgaAuthorizerEntity entity = new IgaAuthorizerEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realmId);
        entity.setProviderId(providerId);
        entity.setType(type);
        entity.setAuthorizer(authorizer);
        entity.setAuthorizerCertificate(authorizerCertificate);
        if (mode != null) {
            entity.setMode(mode);
        }
        entity.setCreatedAt(System.currentTimeMillis());
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * List all authorizers for a realm.
     */
    public List<IgaAuthorizerEntity> listByRealm(String realmId) {
        TypedQuery<IgaAuthorizerEntity> query = em.createNamedQuery(
                "IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * List authorizers for a realm filtered by type.
     */
    public List<IgaAuthorizerEntity> listByRealmAndType(String realmId, String type) {
        TypedQuery<IgaAuthorizerEntity> query = em.createNamedQuery(
                "IgaAuthorizer.findByRealmAndType", IgaAuthorizerEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("type", type);
        return query.getResultList();
    }

    /**
     * Find an authorizer by id. Returns null if not found.
     */
    public IgaAuthorizerEntity findById(String id) {
        return em.find(IgaAuthorizerEntity.class, id);
    }

    /**
     * Delete an authorizer by id.
     */
    public void delete(String id) {
        IgaAuthorizerEntity entity = em.find(IgaAuthorizerEntity.class, id);
        if (entity == null) {
            throw new IllegalArgumentException("Authorizer not found: " + id);
        }
        em.remove(entity);
        em.flush();
    }
}
