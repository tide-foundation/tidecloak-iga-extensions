package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.interfaces.TideUserProvider;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ClientUtils.getFullScopeClients;

public class UserProcessor implements ChangeSetProcessor<TideUserDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideUserDraftEntity entity, EntityManager em, ActionType actionType) {
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.USER)
                .getResultList();
        pendingChanges.forEach(em::remove);

        if (actionType == ActionType.DELETE) {
            entity.setDeleteStatus(DraftStatus.NULL);
        }
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.USER));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideUserDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                List<TideUserDraftEntity> entities = em.createNamedQuery("GetUserEntityByRequestId", TideUserDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitUserChangeRequest(session, realm, entities, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);
    }

    private void commitUserChangeRequest(KeycloakSession session, RealmModel realm, List<TideUserDraftEntity> entities, ChangeSetRequest change, EntityManager em) {
        entities.forEach(entity -> {
            if (change.getActionType() == ActionType.DELETE) {
                if (entity.getDeleteStatus() != DraftStatus.APPROVED) {
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDeleteStatus(DraftStatus.ACTIVE);
                UserModel user = session.users().getUserById(realm, entity.getUser().getId());
                if (user != null) {
                    session.users().removeUser(realm, user);
                }
            }
        });
    }

    @Override
    public void request(KeycloakSession session, TideUserDraftEntity entity, EntityManager em,
                        ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            switch (action) {
                case DELETE:
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(session, em, entity.getChangeRequestId(), changeSetType);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported action for USER: " + action);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to process USER request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        throw new UnsupportedOperationException("USER creation drafting is handled directly in TideUserProvider.addUser()");
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);
        entity.setAction(ActionType.DELETE);

        UserModel user = session.users().getUserById(realm, entity.getUser().getId());
        if (user == null) {
            em.flush();
            return;
        }

        // Get all full-scope clients — user deletion affects all of them
        List<ClientModel> clientList = getFullScopeClients(session, realm, em);

        for (ClientModel client : clientList) {
            ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                    session, em, realm, client, user,
                    new ChangeRequestKey(entity.getId(), changeSetId),
                    ChangeSetType.USER, entity);
        }

        em.flush();
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session,
                                             TideUserDraftEntity entity, UserModel user, ClientModel client) {
        // For user deletion, the resulting token should be empty (user is being removed)
        token.setRealmAccess(null);
        token.setResourceAccess(new HashMap<>());
        return token;
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft,
                                                 Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user,
                                                 EntityManager em) throws Exception {
        // User deletion doesn't affect other users' contexts
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserDraftEntity entity) {
        return null;
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(KeycloakSession session,
                                                               List<TideUserDraftEntity> entities,
                                                               EntityManager em) throws Exception {
        // User deletions are independent — no combining needed
        List<ChangesetRequestEntity> results = new ArrayList<>();
        for (TideUserDraftEntity entity : entities) {
            List<ChangesetRequestEntity> existing = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", entity.getChangeRequestId())
                    .getResultList();
            results.addAll(existing);
        }
        return results;
    }
}
