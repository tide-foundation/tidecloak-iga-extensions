package org.tidecloak.iga.producer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.replay.IgaReplayDispatcher;

import java.util.List;
import java.util.Map;

/**
 * Builds the byte-identical PRODUCER node-unit envelope for a {@code CREATE_*}
 * change request whose target entity does NOT exist yet (it is created only at
 * replay). This is the phase-1 (multiAdmin approval-carrier framing) counterpart
 * of the post-replay node stampers in {@code TideAttestor.stampProducerUnitColumns}.
 *
 * <h2>★ Byte-identity (the load-bearing invariant)</h2>
 * The ork {@code TokenValidationEngine} verifies the realm VVK signature over the
 * LITERAL unit-envelope CBOR the login read re-derives from the committed entity.
 * For a multiAdmin (post-flip) {@code CREATE_*}, the approval carrier is framed at
 * phase-1 — BEFORE the entity exists — so its framed node-unit bytes MUST equal the
 * bytes the post-replay stamper produces from the live entity, or the login replay's
 * batch Ed25519 verify fails.
 *
 * <p>We guarantee that equality BY CONSTRUCTION rather than by re-implementing the
 * rebuild: we run the SAME {@code IgaReplayDispatcher.rebuildCreate*FromRow} helper
 * the real replay calls — into a SCRATCH entity, inside a nested
 * {@code runJobInTransaction} with {@code IGA_REPLAY_ACTIVE=true} — then build the
 * node unit from that live scratch entity via the SAME
 * {@link RealmAttestationExporter} {@code public static} builder the post-replay
 * stamper uses, {@code serialize()} it, and finally ROLL BACK the nested
 * transaction so the scratch entity never persists. Because the rebuild helper AND
 * the producer builder are shared verbatim with the commit path, the phase-1 framing
 * and the post-replay stamp cannot diverge.
 *
 * <p>Only the NODE create units need this from-REP_JSON path (their entity is absent
 * pre-replay). {@code SET_*}/{@code UPDATE_*} node units (entity already exists) and
 * the derived owner-sets are built directly from the live model in
 * {@code TideAttestor} — no scratch rebuild required.
 */
public final class IgaCreateUnitBuilder {

    private static final Logger log = Logger.getLogger(IgaCreateUnitBuilder.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<>() {};

    private IgaCreateUnitBuilder() {}

    /** Is this a CREATE_* action whose node unit must be built from REP_JSON (entity absent pre-replay)? */
    public static boolean isFromRepCreateAction(String actionType) {
        if (actionType == null) return false;
        switch (actionType) {
            case "CREATE_USER":
            case "CREATE_ROLE":
            case "CREATE_GROUP":
            case "CREATE_CLIENT":
            case "CREATE_CLIENT_SCOPE":
                return true;
            default:
                return false;
        }
    }

    /**
     * Build the byte-identical node-unit envelope CBOR for a {@code CREATE_*} CR by
     * replaying its first row into a scratch entity (nested tx, rolled back) and
     * reading the live producer unit. Returns {@code null} only if the scratch
     * rebuild produced no entity (a malformed/owner-unresolvable row — logged).
     *
     * @throws RuntimeException (fail-closed) if the nested rebuild throws.
     */
    public static byte[] nodeUnitCborFromRep(KeycloakSession session, RealmModel realm,
                                             IgaChangeRequestEntity cr) {
        AttestationUnit unit = nodeUnitFromRep(session, realm, cr);
        return unit == null ? null : unit.serialize();
    }

    /**
     * Build the byte-identical node {@link AttestationUnit} for a {@code CREATE_*} CR
     * (see {@link #nodeUnitCborFromRep}). Returned as the typed unit so the caller can
     * both frame its {@code serialize()} bytes at phase-1 AND resolve its column at
     * commit via {@code UnitColumnMapping} — the unit IS its own column descriptor.
     */
    public static AttestationUnit nodeUnitFromRep(KeycloakSession session, RealmModel realm,
                                                  IgaChangeRequestEntity cr) {
        String action = cr.getActionType();
        if (!isFromRepCreateAction(action)) {
            throw new IllegalArgumentException("IgaCreateUnitBuilder: " + action
                    + " is not a from-REP_JSON CREATE action (CR " + cr.getId() + ")");
        }
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        if (rows.isEmpty()) {
            throw new RuntimeException("IgaCreateUnitBuilder: CREATE CR " + cr.getId()
                    + " carries no rows to rebuild a node unit from");
        }
        // A CREATE_* CR is captured per single entity (one row). Use the first row.
        Map<String, Object> row = rows.get(0);
        String realmId = realm.getId();

        // Holder for the unit built inside the scratch (rolled-back) nested tx.
        AttestationUnit[] holder = new AttestationUnit[1];
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), scratch -> {
            // Pass-through the IGA wrappers exactly as the real replay does.
            scratch.setAttribute("IGA_REPLAY_ACTIVE", "true");
            try {
                RealmModel scratchRealm = scratch.realms().getRealm(realmId);
                EntityManager em = scratch.getProvider(JpaConnectionProvider.class).getEntityManager();
                holder[0] = buildScratchUnit(scratch, scratchRealm, em, action, row, realmId);
                // The scratch entity must NEVER persist — it is a pure probe.
                scratch.getTransactionManager().setRollbackOnly();
            } finally {
                scratch.removeAttribute("IGA_REPLAY_ACTIVE");
            }
        });
        if (holder[0] == null) {
            log.warnf("IgaCreateUnitBuilder: scratch rebuild produced no entity for %s CR %s "
                    + "(owner unresolvable?) — no node unit framed", action, cr.getId());
        }
        return holder[0];
    }

    /**
     * Rebuild the scratch entity via the SHARED {@code IgaReplayDispatcher} helper and
     * read the live producer node unit via the SHARED {@link RealmAttestationExporter}
     * builder. Both are the exact methods the real replay + the post-replay stamper use.
     */
    private static AttestationUnit buildScratchUnit(KeycloakSession scratch, RealmModel realm,
                                                    EntityManager em, String action,
                                                    Map<String, Object> row, String realmId) {
        switch (action) {
            case "CREATE_USER" -> {
                IgaReplayDispatcher.rebuildCreateUserFromRow(scratch, realm, row);
                String id = str(row, "ID");
                UserModel u = scratch.users().getUserById(realm, id);
                return u == null ? null : RealmAttestationExporter.userIdentity(u, realmId);
            }
            case "CREATE_ROLE" -> {
                RoleModel r = IgaReplayDispatcher.rebuildCreateRoleFromRow(scratch, realm, row);
                return r == null ? null : RealmAttestationExporter.roleDefinition(r, realmId);
            }
            case "CREATE_GROUP" -> {
                GroupModel g = IgaReplayDispatcher.rebuildCreateGroupFromRow(scratch, realm, row);
                return g == null ? null : RealmAttestationExporter.groupDefinition(g, realmId);
            }
            case "CREATE_CLIENT" -> {
                IgaReplayDispatcher.rebuildCreateClientFromRow(scratch, realm, row);
                String id = str(row, "ID");
                ClientModel c = realm.getClientById(id);
                return c == null ? null : RealmAttestationExporter.clientConfig(c, realmId);
            }
            case "CREATE_CLIENT_SCOPE" -> {
                ClientScopeModel s = IgaReplayDispatcher.rebuildCreateClientScopeFromRow(realm, row);
                return s == null ? null : RealmAttestationExporter.clientScopeConfig(s, realmId);
            }
            default -> throw new IllegalArgumentException("IgaCreateUnitBuilder: unhandled CREATE action " + action);
        }
    }

    private static List<Map<String, Object>> parseRows(String rowsJson) {
        try {
            return MAPPER.readValue(rowsJson, LIST_MAP_REF);
        } catch (Exception e) {
            throw new RuntimeException("IgaCreateUnitBuilder: failed to parse rowsJson", e);
        }
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
    }
}
