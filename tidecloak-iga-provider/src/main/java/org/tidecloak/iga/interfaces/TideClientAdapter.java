package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;

import java.util.*;

public class TideClientAdapter extends ClientAdapter {

    private final boolean isMigration;
    private final ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();

    public TideClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity entity) {
        super(realm, em, session, entity);
        String migrationFlag = System.getenv("IS_MIGRATION");
        this.isMigration = migrationFlag != null && migrationFlag.equalsIgnoreCase("true");
    }

    @Override
    public boolean isFullScopeAllowed() {

        List<TideClientDraftEntity> draft = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();

        return entity.isFullScopeAllowed() || (draft != null && !draft.isEmpty() && draft.get(0).getFullScopeEnabled() == DraftStatus.ACTIVE);
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        try {

            List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();

            List<TideClientDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", entity)
                    .getResultList();

            if(statusDraft.isEmpty()){
                throw new Exception("Client does not exist");
            }
            TideClientDraftEntity clientFullScopeStatuses = statusDraft.get(0);


            if((clientFullScopeStatuses.getDraftStatus().equals(DraftStatus.DRAFT) && !realm.getName().equalsIgnoreCase(Config.getAdminRealm()))
            ) {
                if(!usersInRealm.isEmpty() && clientFullScopeStatuses.getFullScopeDisabled().equals(DraftStatus.DRAFT) && clientFullScopeStatuses.getFullScopeEnabled().equals(DraftStatus.NULL) ){
                    clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
                    return;
                } else if (usersInRealm.isEmpty() && clientFullScopeStatuses.getFullScopeDisabled().equals(DraftStatus.NULL) && clientFullScopeStatuses.getFullScopeEnabled().equals(DraftStatus.DRAFT)) {
                    clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
                    return;
                }
            }

            if(isMigration || realm.getName().equalsIgnoreCase(Config.getAdminRealm())) {
                if(value){
                    clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.NULL);
                    clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
                } else {
                    clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.NULL);
                    clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
                }
                em.flush();
                super.setFullScopeAllowed(value);
                return;
            }

            Runnable callback = () -> {
                try {
                    super.setFullScopeAllowed(value);
                } catch (Exception e) {
                    throw new RuntimeException("Error during FULL_SCOPE callback", e);
                }
            };

            ActionType actionType = value ? ActionType.CREATE : ActionType.DELETE;
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, value, actionType, ChangeSetType.CLIENT_FULLSCOPE);
            changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT_FULLSCOPE).executeWorkflow(session, clientFullScopeStatuses, em, WorkflowType.REQUEST, params, callback);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        return super.addProtocolMapper(model);

    }

    @Override
    public RoleModel addRole(String name) {
        return session.roles().addClientRole(this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return session.roles().addClientRole(this, id, name);
    }

}