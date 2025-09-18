package org.tidecloak.tide.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.ModelException;
import org.keycloak.models.*;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.base.iga.utils.BasicIGAUtils;

import java.util.*;

public final class TideRoleReplaySupport {
    private TideRoleReplaySupport() { }

    public static void createRoleAuthorizerPolicyDraft(
            KeycloakSession session,
            String replayId,
            String certVersion,
            double thresholdPercentage,
            int numberOfAdditionalAdmins,
            RoleModel role
    ) throws Exception {
        String stored = Optional.ofNullable(role.getFirstAttribute("InitCertBundle")).orElse(role.getFirstAttribute("InitCert"));

        String compactBase;
        if (stored != null && stored.trim().startsWith("{")) {
            @SuppressWarnings("unchecked")
            Map<String, String> m = new ObjectMapper().readValue(stored, Map.class);
            compactBase = m.getOrDefault("auth", m.values().stream().findFirst().orElseThrow());
        } else {
            compactBase = stored;
        }

        if (compactBase == null || compactBase.isBlank()) {
            throw new ModelException("Role has no existing InitCert/InitCertBundle to base draft on");
        }

        AuthorizerPolicy prev = AuthorizerPolicy.fromCompact(compactBase);
        int population = Math.max(1, numberOfAdditionalAdmins);
        int newThreshold = Math.max(1, (int)Math.ceil(thresholdPercentage * population));

        List<String> signModels = new ArrayList<>(prev.payload().signmodels == null ? Collections.emptyList() : prev.payload().signmodels);
        AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(compactBase);
        ap.payload().threshold = newThreshold;

        ReplayMetaStore.setRoleInitCert(session, replayId, ap.toCompactString());
    }

    public static void commitRoleAuthorizerPolicy(KeycloakSession session, String replayId, Object mapping, String signature) throws Exception {
        String roleId = BasicIGAUtils.getRoleIdFromEntity(mapping);
        RoleModel roleModel = session.getContext().getRealm().getRoleById(roleId);
        if (roleModel == null) throw new ModelException("Role not found for id=" + roleId);

        String stored = ReplayMetaStore.getRoleInitCert(session, replayId);
        if (stored == null || stored.isBlank()) return;

        if (stored.trim().startsWith("{")) {
            roleModel.setSingleAttribute("InitCertBundle", stored);
            roleModel.removeAttribute("InitCert");
        } else {
            roleModel.setSingleAttribute("InitCert", stored);
            roleModel.removeAttribute("InitCertBundle");
        }
        if (signature != null) roleModel.setSingleAttribute("InitCertSig", signature);

        try {
            String compact = UserContextPolicyHashUtil.unwrapCompactOrFirst(stored);
            AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(compact);
            if (ap.payload().threshold != null) {
                roleModel.setSingleAttribute("tideThreshold", Integer.toString(ap.payload().threshold));
            }
        } catch (Exception ignore) { }

        ReplayMetaStore.clearRoleInitCert(session, replayId);
    }
}
