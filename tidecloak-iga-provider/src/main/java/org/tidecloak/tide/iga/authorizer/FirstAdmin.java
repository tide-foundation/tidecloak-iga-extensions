package org.tidecloak.tide.iga.authorizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.models.UserContext.UserContext;
import org.midgard.models.Policy.*;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.tide.iga.utils.IGAUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;

import java.util.*;
import java.util.stream.Stream;

public class FirstAdmin implements Authorizer {

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, List<?> draftEntities, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        if(changeSet.getType().equals(ChangeSetType.RAGNAROK)) throw new BadRequestException("Only users with the tide-realm-admin role allowed to sign the offboarding request");
        ObjectMapper objectMapper = new ObjectMapper();
        Object draftEntity = draftEntities.get(0);
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));
        if (changesetRequestEntity == null){
            throw new BadRequestException("No change-set request entity found with this recordId and type " + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }
        // Fetch proof details
        List<AccessProofDetailEntity> proofDetails = BasicIGAUtils.getAccessProofs(em, changeSet.getChangeSetId(), changeSet.getType());

        List<UserContext> userContexts = new ArrayList<>();
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        proofDetails.forEach(p -> {
            userContexts.add(new UserContext(p.getProofDraft()));
        });
        RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", role).getSingleResult();

        Policy policy = Policy.From(Base64.getDecoder().decode(tideRoleEntity.getInitCert()));

        if(isAssigningTideRealmAdminRole(draftEntity, session)) {

            // Check if the user to be assigned the Tide Realm Admin role is a tide user
            TideUserRoleMappingDraftEntity userRoleMappingDraft = (TideUserRoleMappingDraftEntity) draftEntity;
            if(userRoleMappingDraft.getUser().getAttributes().stream().noneMatch(a -> a.getName().equalsIgnoreCase("vuid")
                    || a.getName().equalsIgnoreCase("tideuserkey"))) {
                throw new BadRequestException("User needs a tide account linked for the tide-realm-admin role");

            }

            List<String> signatures = IGAUtils.signInitialTideAdmin(componentModel.getConfig(), userContexts.toArray(new UserContext[0]), policy, authorizer, changesetRequestEntity);
            tideRoleEntity.setInitCertSig(signatures.getLast()); // add policy sig
            policy.AddSignature(Base64.getDecoder().decode(signatures.getLast()));
            String rolePolicyString =  Base64.getEncoder().encodeToString(policy.ToBytes());
            tideRoleEntity.setInitCert(rolePolicyString); // add policy sig

            for(int i = 0; i < proofDetails.size(); i++){
                proofDetails.get(i).setSignature(signatures.get(i));
            }
        } else {
            List<String> signatures = IGAUtils.signContextsWithVrk(componentModel.getConfig(), userContexts.toArray(new UserContext[0]), authorizer, changesetRequestEntity);
            for(int i = 0; i < userContexts.size(); i++){
                proofDetails.get(i).setSignature(signatures.get(i));
            }
        }
        em.flush();

        Map<String, String> response = new HashMap<>();
        response.put("message", "Change set signed successfully.");
        response.put("uri", "");
        response.put("changeSetRequests", "");
        response.put("requiresApprovalPopup", "false");


        draftEntities.forEach(d -> {

            BasicIGAUtils.updateDraftStatus(changeSet.getType(), BasicIGAUtils.getActionTypeFromEntity(d), d);
        });

        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        if(changeSet.getType().equals(ChangeSetType.RAGNAROK)) throw new BadRequestException("Offboarding requires a minimum of 3 tide-realm-administrators.");
        ChangeSetProcessorFactory processorFactory = ChangeSetProcessorFactoryProvider.getFactory();// Initialize the processor factory

        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());
        processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);

        if (draftEntity instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
            RoleModel role = realm.getRoleById(tideUserRoleMappingDraftEntity.getRoleId());
            if (role.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)){
                authorizer.setType("multiAdmin");
                // Regenerate default user contexts for all clients when transitioning to multiAdmin
                regenerateDefaultUserContexts(session, realm, em, processorFactory);
            }
        }
        em.flush();
        return Response.ok("Change set approved and committed with authorizer type:  " + authorizer.getType()).build();
    }

    /**
     * Regenerates default user contexts for all clients in the realm.
     * Called when transitioning from firstAdmin to multiAdmin mode.
     */
    private void regenerateDefaultUserContexts(KeycloakSession session, RealmModel realm, EntityManager em, ChangeSetProcessorFactory processorFactory) throws Exception {
        List<ClientModel> clients = realm.getClientsStream().toList();

        for (ClientModel clientModel : clients) {
            ClientEntity client = em.find(ClientEntity.class, clientModel.getId());
            if (client == null) continue;

            List<TideClientDraftEntity> clientDrafts = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", client)
                    .getResultList();
            if (clientDrafts.isEmpty()) continue;

            for (TideClientDraftEntity draft : clientDrafts) {
                // Remove existing Access Proofs
                List<AccessProofDetailEntity> accessProof = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", draft.getChangeRequestId()).getResultList();
                accessProof.forEach(em::remove);

                // Remove existing ChangeSetRequestEntity
                ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class,
                        new ChangesetRequestEntity.Key(draft.getChangeRequestId(), ChangeSetType.CLIENT));
                if (changesetRequestEntity != null) {
                    changesetRequestEntity.getAdminAuthorizations().clear();
                    em.remove(changesetRequestEntity);
                }

                // Execute Workflow to regenerate
                draft.setDraftStatus(DraftStatus.DRAFT);
                WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
                processorFactory.getProcessor(ChangeSetType.CLIENT)
                        .executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
            }
        }
    }

    private boolean isAssigningTideRealmAdminRole(Object draftEntity, KeycloakSession session){
        if(draftEntity instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
            RoleModel tideRole = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            return tideUserRoleMappingDraftEntity.getRoleId().equals(tideRole.getId());
        }
        return false;

    }
}
