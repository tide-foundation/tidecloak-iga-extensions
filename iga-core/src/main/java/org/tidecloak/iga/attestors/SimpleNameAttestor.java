package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Default {@link IgaAttestor} that performs no cryptography. It simply records
 * the authorizing admin's username as the "attestation" and combines all the
 * recorded usernames + timestamps into a small JSON array.
 *
 * <p>Scope-based authorization is enforced via {@link IgaScopeResolver} before
 * the authorization is persisted: when a group, role or client affected by
 * the change request carries an {@code iga.approverRole} attribute, the admin
 * must hold the named realm role (or roles, when {@code iga.scopeMode=all}).
 */
public class SimpleNameAttestor implements IgaAttestor {

    public static final String ID = "simple";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public SimpleNameAttestor(KeycloakSession session) {
        // session is supplied via the per-call parameter; constructor arg is kept
        // to match the factory's create(session) wiring.
    }

    @Override
    public String getId() {
        return ID;
    }

    /**
     * Stable principal recorded when no human admin {@link UserModel} is resolvable for
     * the authorization — i.e. a system-bootstrap auto-commit (firstAdmin ADOPT sweep,
     * threshold=1, approver-gate bypassed) driven by a cross-realm caller who cannot be
     * re-loaded in the job session. Recording this instead of NPEing keeps the whole
     * sweep from aborting (every ADOPT CR → AUTHORIZE_FAILED) and leaves an honest audit
     * marker that the actor was the system, not an individual admin.
     */
    public static final String SYSTEM_PRINCIPAL = "iga-system-bootstrap";

    @Override
    public IgaAuthorizationEntity record(KeycloakSession session,
                                         IgaChangeRequestEntity cr,
                                         UserModel admin,
                                         String attestationPayload) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        // ADOPT_* CRs bypass the approver-role gate inside
        // requireApprover — they are a system-bootstrap onramp, not a
        // governance decision. The action-type-aware overload handles that
        // short-circuit; all other action types enforce the gate as before.
        // (requireApprover is null-admin-safe for exactly these bypassed paths —
        // ADOPT / firstAdmin return before any admin deref; a non-bypassed CR with
        // a null admin still fails the gate, which is correct.)
        IgaScopeResolver.requireApprover(session, realm, admin, scope, cr);

        // Null-admin tolerance: the system-bootstrap sweep can arrive with no resolvable
        // UserModel (cross-realm super-admin not present in the job session's realm). Record
        // a stable system principal rather than NPE — guarantees a missing admin can never
        // again abort the firstAdmin ADOPT sweep at SimpleNameAttestor.record.
        String authorizedBy = admin != null ? admin.getId() : SYSTEM_PRINCIPAL;
        String approvalName = admin != null ? admin.getUsername() : SYSTEM_PRINCIPAL;

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(authorizedBy);
        // The "name" is the attestation for the simple attestor; ignore attestationPayload.
        auth.setApproval(approvalName);
        auth.setCreatedAt(System.currentTimeMillis());
        em.persist(auth);
        em.flush();
        return auth;
    }

    @Override
    public String combineFinal(KeycloakSession session,
                               IgaChangeRequestEntity cr,
                               List<IgaAuthorizationEntity> authorizations) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (authorizations != null) {
            for (IgaAuthorizationEntity a : authorizations) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("by", a.getApproval());
                entry.put("at", a.getCreatedAt());
                list.add(entry);
            }
        }
        try {
            return MAPPER.writeValueAsString(list);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize SimpleNameAttestor final attestation", e);
        }
    }

    @Override
    public int getThreshold(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        // ADOPT_* CRs short-circuit to threshold=1 inside the resolver — see
        // resolveThreshold's javadoc. All other action types use the regular
        // realm/per-scope threshold resolution.
        return IgaScopeResolver.resolveThreshold(session, realm, scope, cr);
    }

    @Override
    public void close() {
    }
}
