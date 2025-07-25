package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
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
            // Dont draft for master realm
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                super.setFullScopeAllowed(value);
                return;
            }

            List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();

            List<TideClientDraftEntity> statusDraft = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", entity)
                    .getResultList();
            if(!statusDraft.isEmpty()){
                TideClientDraftEntity clientFullScopeStatuses = statusDraft.get(0);
                if((clientFullScopeStatuses.getFullScopeEnabled().equals(DraftStatus.ACTIVE) && value) || (clientFullScopeStatuses.getFullScopeDisabled().equals(DraftStatus.ACTIVE) && !value)) {
                    super.setFullScopeAllowed(value);
                    CacheRealmProvider cacheRealmProvider = session.getProvider(CacheRealmProvider.class);
                    cacheRealmProvider.registerClientInvalidation(entity.getId(), entity.getId(), realm.getId());
                    return;
                }

                if((value && !clientFullScopeStatuses.getFullScopeEnabled().equals(DraftStatus.NULL)) || (!value && !clientFullScopeStatuses.getFullScopeDisabled().equals(DraftStatus.NULL))) {
                    return;
                }

                if((clientFullScopeStatuses.getDraftStatus().equals(DraftStatus.DRAFT) && !realm.getName().equalsIgnoreCase(Config.getAdminRealm()))) {
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
            } else {
                TideClientDraftEntity clientDraftEntity = new TideClientDraftEntity();
                clientDraftEntity.setId(KeycloakModelUtils.generateId());
                clientDraftEntity.setClient(entity);

                if(usersInRealm.isEmpty()) {
                    clientDraftEntity.setFullScopeEnabled(DraftStatus.ACTIVE);
                    clientDraftEntity.setFullScopeDisabled(DraftStatus.NULL);
                    entity.setFullScopeAllowed(true);
                } else {
                    clientDraftEntity.setFullScopeDisabled(DraftStatus.ACTIVE);
                    clientDraftEntity.setFullScopeEnabled(DraftStatus.NULL);
                    entity.setFullScopeAllowed(false);
                }
                clientDraftEntity.setAction(ActionType.CREATE);
                em.persist(clientDraftEntity);
                em.flush();
                String igaAttribute = realm.getAttribute("isIGAEnabled");
                boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");
                if(isIGAEnabled) {
                    WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
                    changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT).executeWorkflow(session, clientDraftEntity, em, WorkflowType.REQUEST, params, null);
                }
            }

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