package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.tide.iga.utils.IGAUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;

import java.util.*;
import java.util.stream.Stream;

public class FirstAdmin implements Authorizer {

    private static final ObjectMapper M = new ObjectMapper();

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet,
                                       EntityManager em,
                                       KeycloakSession session,
                                       RealmModel realm,
                                       Object draftEntity,
                                       AdminAuth auth,
                                       AuthorizerEntity authorizer,
                                       ComponentModel componentModel) throws Exception {
        if(changeSet.getType().equals(ChangeSetType.RAGNAROK)) throw new BadRequestException("Only users with the tide-realm-admin role allowed to sign the offboarding request");

        ChangesetRequestEntity changesetRequestEntity = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (changesetRequestEntity == null) {
            throw new BadRequestException("No change-set request entity found for recordId/type: "
                    + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }

        // 1) Load proofs and build user-contexts (admins first, then normal)
        List<AccessProofDetailEntity> proofs = BasicIGAUtils.getAccessProofs(em, changeSet.getChangeSetId(), changeSet.getType());
        proofs.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        List<UserContext> contexts = new ArrayList<>(proofs.size());
        for (AccessProofDetailEntity p : proofs) contexts.add(new UserContext(p.getProofDraft()));

        Stream<UserContext> admin = contexts.stream().filter(x -> x.getInitCertHash() != null);
        Stream<UserContext> normal = contexts.stream().filter(x -> x.getInitCertHash() == null);
        List<UserContext> orderedContexts = Stream.concat(admin, normal).toList();

        // 2) If this is Tide Realm Admin role assignment, compute policyRefs (auth/sign) from role AP bundle
        //    (The bundle is saved in the role draft initCert column as {"auth":"h.p[.sig]","sign":"h.p[.sig]"} or legacy single compact.)
        Map<String, List<String>> policyRefs = null;
        if (isAssigningTideRealmAdminRole(draftEntity, session)) {
            RoleModel tideRole = session.clients()
                    .getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

            RoleEntity roleEntity = em.getReference(RoleEntity.class, tideRole.getId());
            TideRoleDraftEntity roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                    .setParameter("role", roleEntity)
                    .getSingleResult();

            String apBundle = roleDraft.getInitCert(); // now stores both AP compacts or a single legacy compact
            policyRefs = IGAUtils.buildPolicyRefs(apBundle);
            // If your request model supports extra claims, we will add these in IGAUtils.signContextsWithVrk (commented)
        }

        // 3) Sign with VRK (no InitCert involved anymore)
        List<String> signatures = IGAUtils.signContextsWithVrk(
                componentModel.getConfig(),
                orderedContexts.toArray(new UserContext[0]),
                authorizer,
                changesetRequestEntity
        );

        // 4) Persist returned signatures back onto proofs (respect ordering used by request)
        //    Keep the same “admins first, then normal” ordering to align with signatures[].
        Stream<AccessProofDetailEntity> adminProofs = proofs.stream().filter(x -> new UserContext(x.getProofDraft()).getInitCertHash() != null);
        Stream<AccessProofDetailEntity> normalProofs = proofs.stream().filter(x -> new UserContext(x.getProofDraft()).getInitCertHash() == null);
        List<AccessProofDetailEntity> orderedProofs = Stream.concat(adminProofs, normalProofs).toList();

        if (orderedProofs.size() != signatures.size()) {
            throw new IllegalStateException("Signature count mismatch. contexts=" + orderedProofs.size() + " sigs=" + signatures.size());
        }
        for (int i = 0; i < orderedProofs.size(); i++) {
            orderedProofs.get(i).setSignature(signatures.get(i));
        }

        em.flush();

        Map<String, String> response = new HashMap<>();
        response.put("message", "Change set signed successfully.");
        response.put("uri", "");
        response.put("changeSetRequests", "");
        response.put("requiresApprovalPopup", "false");


        draftEntities.forEach(d -> {

            BasicIGAUtils.updateDraftStatus(BasicIGAUtils.getTypeFromEntity(d), BasicIGAUtils.getActionTypeFromEntity(d), d);
        });

        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet,
                                         EntityManager em,
                                         KeycloakSession session,
                                         RealmModel realm,
                                         Object draftEntity,
                                         AdminAuth auth,
                                         AuthorizerEntity authorizer,
                                         ComponentModel componentModel) throws Exception {
        if(changeSet.getType().equals(ChangeSetType.RAGNAROK)) throw new BadRequestException("Offboarding requires a minimum of 3 tide-realm-administrators.");

        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();
        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());

        processorFactory.getProcessor(changeSet.getType())
                .executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);

        if (draftEntity instanceof TideUserRoleMappingDraftEntity mapping) {
            RoleModel role = realm.getRoleById(mapping.getRoleId());
            if (role.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
                authorizer.setType("multiAdmin");
            }
        }
        em.flush();
        return Response.ok("Change set approved and committed with authorizer type: " + authorizer.getType()).build();
    }

    private boolean isAssigningTideRealmAdminRole(Object draftEntity, KeycloakSession session) {
        if (draftEntity instanceof TideUserRoleMappingDraftEntity mapping) {
            RoleModel tideRole = session.getContext().getRealm()
                    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            return mapping.getRoleId().equals(tideRole.getId());
        }
        return false;
    }
}
