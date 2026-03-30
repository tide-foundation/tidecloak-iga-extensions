package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.drafting.TideGroupRoleMappingEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;

public class TideGroupAdapter extends GroupAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final ChangeSetProcessorFactory changeSetProcessorFactory;

    public TideGroupAdapter(RealmModel realm, EntityManager em, GroupEntity group, KeycloakSession session) {
        super(session, realm, em, group);
        this.session = session;
        this.realm = realm;
        this.changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
    }

    @Override
    public void grantRole(RoleModel role) {
        BasicIGAUtils.stampRequestingAdmin(session);
        try {
            // Don't draft for master realm — apply directly
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) {
                super.grantRole(role);
                return;
            }

            // Check if a draft already exists for this group+role
            List<TideGroupRoleMappingEntity> existing = em.createNamedQuery("groupRoleMappingDraftsByStatusAndGroupAndRole", TideGroupRoleMappingEntity.class)
                    .setParameter("group", getEntity())
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.DRAFT)
                    .getResultList();

            if (!existing.isEmpty()) {
                return;
            }

            TideGroupRoleMappingEntity entity = new TideGroupRoleMappingEntity();
            entity.setId(KeycloakModelUtils.generateId());
            entity.setGroup(getEntity());
            entity.setRoleId(role.getId());
            entity.setDraftStatus(DraftStatus.DRAFT);
            entity.setAction(ActionType.CREATE);
            em.persist(entity);
            em.flush();

            ChangeSetProcessor<TideGroupRoleMappingEntity> processor = changeSetProcessorFactory.getProcessor(ChangeSetType.GROUP_ROLE);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.GROUP_ROLE);
            processor.executeWorkflow(session, entity, em, WorkflowType.REQUEST, params, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        BasicIGAUtils.stampRequestingAdmin(session);
        try {
            // Don't draft for master realm
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) {
                super.deleteRoleMapping(role);
                return;
            }

            // Check if there's an uncommitted draft — if so, just remove it directly
            List<TideGroupRoleMappingEntity> draftEntities = em.createNamedQuery("groupRoleMappingDraftsByStatusAndGroupAndRole", TideGroupRoleMappingEntity.class)
                    .setParameter("group", getEntity())
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.DRAFT)
                    .getResultList();

            if (!draftEntities.isEmpty()) {
                // Role was never applied to base table (only draft exists), just remove the draft
                em.createNamedQuery("deleteGroupRoleMappingDraftsByRole")
                        .setParameter("roleId", role.getId())
                        .executeUpdate();
                return;
            }

            // Check for active (committed) drafts
            List<TideGroupRoleMappingEntity> activeEntities = em.createNamedQuery("groupRoleMappingDraftsByStatusAndGroupAndRole", TideGroupRoleMappingEntity.class)
                    .setParameter("group", getEntity())
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .getResultList();

            if (activeEntities.isEmpty()) {
                super.deleteRoleMapping(role);
                return;
            }

            TideGroupRoleMappingEntity committedEntity = activeEntities.get(0);

            ChangeSetProcessor<TideGroupRoleMappingEntity> processor = changeSetProcessorFactory.getProcessor(ChangeSetType.GROUP_ROLE);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.GROUP_ROLE);
            processor.executeWorkflow(session, committedEntity, em, WorkflowType.REQUEST, params, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        em.flush();
    }

    /**
     * Applies the role grant directly to the base Keycloak table.
     * Called during the COMMIT phase after a draft has been approved.
     */
    public void applyGrantRole(RoleModel role) {
        super.grantRole(role);
    }

    /**
     * Applies the role removal directly from the base Keycloak table.
     * Called during the COMMIT phase after a deletion draft has been approved.
     */
    public void applyDeleteRoleMapping(RoleModel role) {
        super.deleteRoleMapping(role);
    }

    public Stream<RoleModel> getRealmRoleMappingsStreamByStatus(DraftStatus draftStatus) {
        return getRoleMappingsStreamByStatus(draftStatus).filter(RoleUtils::isRealmRole);
    }


    public Stream<RoleModel> getRoleMappingsStreamByStatus(DraftStatus draftStatus) {
        // Get roles from draft table with matching status
        TypedQuery<String> query = em.createNamedQuery("groupRoleMappingDraftIdsByStatus", String.class);
        query.setParameter("group", getEntity());
        query.setParameter("draftStatus", draftStatus);
        Set<RoleModel> draftRoles = query.getResultStream()
                .map(realm::getRoleById).filter(Objects::nonNull)
                .collect(Collectors.toSet());

        if (draftStatus == DraftStatus.ACTIVE) {
            // Also include roles from the base GROUP_ROLE_MAPPING table that have no draft entry.
            // These are roles assigned before IGA was enabled or that bypassed the draft flow.
            super.getRoleMappingsStream().forEach(baseRole -> {
                if (!draftRoles.contains(baseRole)) {
                    draftRoles.add(baseRole);
                }
            });
        }

        return draftRoles.stream();
    }
    public Stream<RoleModel> getRoleMappingsStreamByStatusAndAction(DraftStatus draftStatus, ActionType actionType) {
        // we query ids only as the role might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        TypedQuery<String> query = em.createNamedQuery("groupRoleMappingDraftIdsByStatus", String.class);
        query.setParameter("group", getEntity());
        query.setParameter("draftStatus", draftStatus);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

}
