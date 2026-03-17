package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resource.RealmResourceProvider;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.Map;
import org.midgard.models.Policy.*;


public class PolicyResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public PolicyResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @Path("policy")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getPolicy(@PathParam("roleId") String roleId, @PathParam("clientId") String clientId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel role = session.clients().getClientByClientId(session.getContext().getRealm(), clientId).getRole(roleId);
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getSingleResult();
        Policy policy = Policy.From(Base64.getDecoder().decode(tideRoleEntity.getInitCert()));

        return Response.ok(policy.toString()).build();
    }

    @GET
    @Path("admin-policy")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAdminPolicy() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel role = session.clients().getClientByClientId(session.getContext().getRealm(), Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getSingleResult();
        return Response.ok(tideRoleEntity.getInitCert()).build();
    }

    @GET
    @Path("admin-policy/bytes")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAdminPolicyBytes() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel client = session.clients().getClientByClientId(session.getContext().getRealm(), Constants.REALM_MANAGEMENT_CLIENT_ID);
        if (client == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Realm management client not found").build();
        }
        RoleModel role = client.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        if (role == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Tide realm admin role not found").build();
        }
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getSingleResult();
        return Response.ok(Base64.getDecoder().decode(tideRoleEntity.getInitCert())).build();
    }

    @GET
    @Path("admin-policy/display")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getAdminPolicyDisplay() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel client = session.clients().getClientByClientId(session.getContext().getRealm(), Constants.REALM_MANAGEMENT_CLIENT_ID);
        if (client == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Realm management client not found").build();
        }
        RoleModel role = client.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        if (role == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Tide realm admin role not found").build();
        }
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getSingleResult();
        Policy policy = Policy.From(Base64.getDecoder().decode(tideRoleEntity.getInitCert()));
        return Response.ok(policy.toString()).build();
    }

}
