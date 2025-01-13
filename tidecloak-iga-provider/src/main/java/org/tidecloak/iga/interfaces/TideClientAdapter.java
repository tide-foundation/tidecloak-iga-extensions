package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
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
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;

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

        List<TideClientFullScopeStatusDraftEntity> draft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("client", entity)
                .getResultList();

        return entity.isFullScopeAllowed() || (draft != null && !draft.isEmpty() && draft.get(0).getFullScopeEnabled() == DraftStatus.ACTIVE);
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        try {
            List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
            List<TideClientFullScopeStatusDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                    .setParameter("client", entity)
                    .getResultList();

            // if no users and no drafts
            if (usersInRealm.isEmpty() && statusDraft.isEmpty()) {
                createFullScopeStatusDraft(value);
                super.setFullScopeAllowed(value);
                return;
            }

            if(isMigration) {
                if(value){
                    statusDraft.get(0).setFullScopeDisabled(DraftStatus.NULL);
                    statusDraft.get(0).setFullScopeEnabled(DraftStatus.ACTIVE);
                } else {
                    statusDraft.get(0).setFullScopeEnabled(DraftStatus.NULL);
                    statusDraft.get(0).setFullScopeDisabled(DraftStatus.ACTIVE);
                }
                em.flush();
                super.setFullScopeAllowed(value);
                return;
            }

            // if theres users and no drafts
            else if (!usersInRealm.isEmpty() && statusDraft.isEmpty()) {
                createFullScopeStatusDraft(false); // New clients defaults to restricted scope if there are users in the realm.
                return;
            }

            Runnable callback = () -> {
                try {
                    super.setFullScopeAllowed(value);
                } catch (Exception e) {
                    throw new RuntimeException("Error during FULL_SCOPE callback", e);
                }
            };

            TideClientFullScopeStatusDraftEntity clientFullScopeStatuses = statusDraft.get(0);
            ActionType actionType = value ? ActionType.CREATE : ActionType.DELETE;
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, value, actionType);
            changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT_FULLSCOPE).executeWorkflow(session, clientFullScopeStatuses, em, WorkflowType.REQUEST, params, callback);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
    private void createFullScopeStatusDraft(boolean value) {
        TideClientFullScopeStatusDraftEntity draft = new TideClientFullScopeStatusDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setClient(entity);
        if (value) {
            draft.setFullScopeEnabled(DraftStatus.ACTIVE);
            draft.setFullScopeDisabled(DraftStatus.NULL);
        } else {
            draft.setFullScopeDisabled(DraftStatus.ACTIVE);
            draft.setFullScopeEnabled(DraftStatus.NULL);
        }
        draft.setAction(ActionType.CREATE);
        em.persist(draft);
        em.flush();
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