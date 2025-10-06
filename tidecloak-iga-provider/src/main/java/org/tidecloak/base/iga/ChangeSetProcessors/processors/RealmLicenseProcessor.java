package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.midgard.Serialization.Tools;
import org.midgard.models.ModelRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.ChangeRequestKey;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.LicenseHistory;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.LicensingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

public class RealmLicenseProcessor implements org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor<LicensingDraftEntity> {
    protected static final Logger logger = Logger.getLogger(RealmLicenseProcessor.class);

    @Override
    public void cancel(KeycloakSession session, LicensingDraftEntity entity, EntityManager em, ActionType actionType){
        String realmId = session.getContext().getRealm().getId();

        em.createNamedQuery("LicensingDraft.deleteByRealm")
                .setParameter("realmId", realmId)
                .executeUpdate();

        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.REALM_LICENSING));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void request(KeycloakSession session, LicensingDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Requests ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId(),
                    entity.getChangeRequestId()
            ));
            if (Objects.requireNonNull(action) == ActionType.CREATE) {
                logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                handleCreateRequest(session, entity, em, callback);
                ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                callback.run();
            } else {
                logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", action, entity.getId(), entity.getChangeRequestId()));
                throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process USER_ROLE request", e);
        }
    }


    @Override
    public void handleCreateRequest(KeycloakSession keycloakSession, LicensingDraftEntity licensingDraftEntity, EntityManager entityManager, Runnable runnable) throws Exception {
        RealmModel realm = keycloakSession.getContext().getRealm();
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            logger.warn("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }
        String changeSetId = KeycloakModelUtils.generateId();
        licensingDraftEntity.setChangeRequestId(changeSetId);
    }

    @Override
    public void handleDeleteRequest(KeycloakSession keycloakSession, LicensingDraftEntity licensingDraftEntity, EntityManager entityManager, Runnable runnable) throws Exception {
        throw new Exception("Not implemented");
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession keycloakSession, AccessProofDetailEntity accessProofDetailEntity, Set<RoleModel> set, ClientModel clientModel, TideUserAdapter tideUserAdapter, EntityManager entityManager) throws Exception {
        throw new Exception("Not implemented");

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession keycloakSession, RealmModel realmModel, LicensingDraftEntity licensingDraftEntity) {
        return null;
    }

    public void saveDraftReq(LicensingDraftEntity entity, EntityManager em, RealmModel realm, String gvrk) {
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.REALM_LICENSING));
        if (changesetRequestEntity == null) {
            ChangesetRequestEntity cre = new ChangesetRequestEntity();
            cre.setChangesetRequestId(entity.getChangeRequestId());
            cre.setDraftRequest(Base64.getEncoder().encodeToString(Base64.getEncoder().encode(DatatypeConverter.parseHexBinary(gvrk))));
            cre.setChangesetType(ChangeSetType.REALM_LICENSING);
            em.persist(entity);
            em.flush();
        } else {
            changesetRequestEntity.setDraftRequest(Base64.getEncoder().encodeToString(Base64.getEncoder().encode(DatatypeConverter.parseHexBinary(gvrk))));
            em.flush();
        }
    }
}