package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public final class UserContextDraftService {

    private UserContextDraftService() {}

    /** (userId, clientId, delta payload) triple used at staging time. */
    public static final class AffectedTuple {
        public final String userId;
        public final String clientId; // clientId (alias); we resolve DB id below
        public final Map<String, Object> delta;
        public AffectedTuple(String userId, String clientId, Map<String, Object> delta) {
            this.userId = userId; this.clientId = clientId; this.delta = delta;
        }
    }

    /** Stage drafts for a changeSet across many (user,client) tuples. */
    public static void stage(KeycloakSession session,
                             RealmModel realm,
                             EntityManager em,
                             String changeSetId,
                             ChangeSetType type,
                             List<AffectedTuple> affected,
                             String authorizerPolicyHashBase64 // nullable, already Base64
    ) throws Exception {
        if (affected == null || affected.isEmpty()) {
            throw new BadRequestException("No affected users/clients to stage for changeSetId=" + changeSetId);
        }

        // Ensure ChangesetRequest envelope exists (no ensureRequestExists call)
        ChangesetRequestEntity cre = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSetId, type));
        if (cre == null) {
            cre = new ChangesetRequestEntity();
            cre.setChangesetRequestId(changeSetId);
            cre.setChangesetType(type);
            byte[] draftBlob = ("{\"changeSetId\":\""+changeSetId+"\",\"type\":\""+type+"\"}")
                    .getBytes(StandardCharsets.UTF_8);
            cre.setDraftRequest(Base64.getEncoder().encodeToString(draftBlob));
            em.persist(cre);
        }

        for (AffectedTuple t : affected) {
            UserModel user = session.users().getUserById(realm, t.userId);
            ClientModel client = session.clients().getClientByClientId(realm, t.clientId);
            if (user == null || client == null) continue;

            ObjectNode defCtx = UserContextBuilder.build(session, realm, user, client);
            ObjectNode txCtx  = UserContextBuilder.buildWithDelta(session, realm, user, client, t.delta);

            // Attach transitive AuthorizerPolicies (direct/group/composite)
            UserContextBuilder.attachAuthorizerPolicies(session, realm, user, client, txCtx);

            AccessProofDetailEntity pd = findOrCreateDraft(em, session, realm, changeSetId, type, user, client);
            pd.setDefaultUserContext(defCtx.toString());
            pd.setProofDraft(txCtx.toString());
            if (authorizerPolicyHashBase64 != null && !authorizerPolicyHashBase64.isBlank()) {
                pd.setAuthorizerPolicyHash(authorizerPolicyHashBase64);
            }
            pd.setDraftStatus(DraftStatus.DRAFT);
            em.persist(pd);
        }

        em.flush();
    }

    /** Commit a single changeSet: sign/approve, promote to active, then rebase others. */
    public static void commit(KeycloakSession session,
                              RealmModel realm,
                              EntityManager em,
                              ChangesetRequestEntity request,
                              AdminAuth auth,
                              CommitHook hook
    ) throws Exception {
        List<AccessProofDetailEntity> drafts = em.createNamedQuery(
                        "getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", request.getChangesetRequestId())
                .getResultList();

        if (drafts.isEmpty()) {
            throw new BadRequestException("No drafts found for " + request.getChangesetRequestId());
        }

        List<String> ctxJsons = drafts.stream().map(AccessProofDetailEntity::getProofDraft).toList();
        List<String> signatures = hook.signOrApprove(session, realm, request, ctxJsons, auth);

        for (int i = 0; i < drafts.size(); i++) {
            AccessProofDetailEntity d = drafts.get(i);
            String sig = (signatures.size() > i) ? signatures.get(i) : "";
            promoteToActive(em, d, sig);
            em.remove(d);
        }

        em.remove(request);
        em.flush();

        rebaseOpenDrafts(session, realm, em, request.getChangesetRequestId());
    }

    /** Rebuild the proofDraft of EVERY open draft not matching committedChangeSetId. */
    public static void rebaseOpenDrafts(KeycloakSession session,
                                        RealmModel realm,
                                        EntityManager em,
                                        String committedChangeSetId) {
        List<AccessProofDetailEntity> allOpen = em.createNamedQuery(
                        "getProofDetailsForRealm", AccessProofDetailEntity.class)
                .setParameter("realmId", realm.getId())
                .getResultList()
                .stream()
                .filter(p -> !Objects.equals(p.getChangeRequestKey().getChangeRequestId(), committedChangeSetId))
                .collect(Collectors.toList());

        for (AccessProofDetailEntity pd : allOpen) {
            UserModel user = session.users().getUserById(realm, pd.getUser().getId());
            ClientModel client = session.clients().getClientById(realm, pd.getClientId());
            if (user == null || client == null) continue;

            Map<String, Object> delta = UserContextDeltaUtils.deriveDelta(pd.getDefaultUserContext(), pd.getProofDraft());

            ObjectNode defCtx = UserContextBuilder.build(session, realm, user, client);
            ObjectNode txCtx  = UserContextBuilder.buildWithDelta(session, realm, user, client, delta);
            UserContextBuilder.attachAuthorizerPolicies(session, realm, user, client, txCtx);

            pd.setDefaultUserContext(defCtx.toString());
            pd.setProofDraft(txCtx.toString());
            pd.setDraftStatus(DraftStatus.DRAFT);
        }

        em.flush();
    }

    // ─────────────── internals ───────────────

    private static AccessProofDetailEntity findOrCreateDraft(EntityManager em,
                                                             KeycloakSession session,
                                                             RealmModel realm,
                                                             String changeSetId,
                                                             ChangeSetType type,
                                                             UserModel user,
                                                             ClientModel client) {
        List<AccessProofDetailEntity> existing = em.createNamedQuery(
                        "getProofDetailsForUserByClientAndRecordId", AccessProofDetailEntity.class)
                .setParameter("user", em.getReference(UserEntity.class, user.getId()))
                .setParameter("clientId", client.getId())
                .setParameter("recordId", changeSetId)
                .getResultList();
        if (!existing.isEmpty()) return existing.get(0);

        AccessProofDetailEntity pd = new AccessProofDetailEntity();
        pd.setId(UUID.randomUUID().toString());
        pd.setChangeRequestKey(new ChangeRequestKey(changeSetId, null));
        pd.setChangesetType(type);
        pd.setUser(em.getReference(UserEntity.class, user.getId()));
        pd.setClientId(client.getId());
        pd.setRealmId(realm.getId());
        pd.setCreatedTimestamp(System.currentTimeMillis());
        return pd;
    }

    private static void promoteToActive(EntityManager em, AccessProofDetailEntity draft, String signature) {
        UserClientAccessProofEntity.Key key =
                new UserClientAccessProofEntity.Key(draft.getUser(), draft.getClientId());
        UserClientAccessProofEntity active = em.find(UserClientAccessProofEntity.class, key);
        if (active == null) {
            active = new UserClientAccessProofEntity();
            active.setUser(draft.getUser());
            active.setClientId(draft.getClientId());
            active.setIdProofSig("");
            active.setAccessProofMeta("");
            em.persist(active);
        }
        active.setAccessProof(draft.getProofDraft());
        active.setAccessProofSig((signature == null) ? "" : signature);
        em.merge(active);
    }

    /** Strategy hook: Tide signatures or base-IGA approvals. */
    public interface CommitHook {
        List<String> signOrApprove(KeycloakSession session,
                                   RealmModel realm,
                                   ChangesetRequestEntity request,
                                   List<String> userContextJsons,
                                   AdminAuth auth) throws Exception;
    }
}
