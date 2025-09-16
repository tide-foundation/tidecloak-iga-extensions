// 
package org.tidecloak.preview.rest;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resource.RealmResourceProvider;
import org.tidecloak.preview.authz.PolicyLinker;
import org.tidecloak.jpa.entities.preview.TokenPreviewBundleEntity;
import org.tidecloak.jpa.entities.preview.TokenPreviewEntity;
import org.tidecloak.preview.dto.TokenPreviewBundleSpec;
import org.tidecloak.preview.dto.TokenPreviewSpec;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.models.utils.RoleUtils;

import org.tidecloak.jpa.entities.preview.TokenPreviewBundleEntity;
import org.tidecloak.jpa.entities.preview.TokenPreviewEntity;

import org.tidecloak.preview.util.TokenPreviewBuilder;
import org.tidecloak.preview.service.RevisionService;
import org.tidecloak.preview.util.PreviewBundleConsolidator;
import org.tidecloak.preview.util.TokenDiffUtil;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Path("/token-preview")
public class TokenPreviewRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public TokenPreviewRealmResourceProvider(KeycloakSession session) { this.session = session; }

    @Override public Object getResource() { return this; }
    @Override public void close() { }

    private RealmModel realm() { return session.getContext().getRealm(); }

    @POST @Path("/") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response createPreview(TokenPreviewSpec spec) {
        RevisionService rs = new RevisionService(session);
        long activeRev = rs.getActiveRev(realm());
        if (spec != null && spec.expectedActiveRev != null && spec.expectedActiveRev.longValue() != activeRev) {
            throw new ClientErrorException("Active context revision mismatch", 409);
        }

        RealmModel realm = realm();

        // Default client "userless" context when no userId provided
        if (spec != null && spec.userId == null) {
            if (spec.clientId == null) throw new BadRequestException("clientId required for defaultClientContext");
            ClientModel client = session.clients().getClientByClientId(realm, spec.clientId);
            if (client == null) throw new NotFoundException("Client not found: " + spec.clientId);

            Map<String,Object> tok = new LinkedHashMap<>();
            tok.put("iss", realm.getName() != null ? realm.getName() : "");
            tok.put("azp", client.getClientId());

            // realm_access from default roles
            RoleModel def = realm.getDefaultRole();
            if (def != null) {
                Set<String> rr = new TreeSet<>();
                org.keycloak.models.utils.RoleUtils.expandCompositeRolesStream(java.util.stream.Stream.of(def))
                        .forEach(role -> rr.add(role.getName()));
                if (!rr.isEmpty()) {
                    Map<String,Object> ra = new LinkedHashMap<>();
                    ra.put("roles", new ArrayList<>(rr));
                    tok.put("realm_access", ra);
                }
            }

            // if full scope, add common account roles if present
            if (client.isFullScopeAllowed()) {
                ClientModel account = session.clients().getClientByClientId(realm, "account");
                if (account != null) {
                    List<String> names = Arrays.asList("manage-account", "manage-account-links", "view-profile");
                    List<String> present = new ArrayList<>();
                    for (String n : names) { if (account.getRole(n) != null) present.add(n); }
                    if (!present.isEmpty()) {
                        Map<String,Object> ra = new LinkedHashMap<>();
                        ra.put("roles", present);
                        Map<String,Object> res = new LinkedHashMap<>();
                        res.put("account", ra);
                        tok.put("resource_access", res);
                        tok.put("aud", "account");
                    }
                }
            }

            Map<String,Object> out = new LinkedHashMap<>();
            out.put("baselineToken", tok);
            out.put("previewToken", tok);
            out.put("diff", Collections.emptyList());
            out.put("activeRev", activeRev);
            return Response.ok(out).build();
        }

        if (spec == null || spec.userId == null || spec.clientId == null) {
            throw new BadRequestException("userId and clientId are required");
        }

        UserModel user = session.users().getUserById(realm, spec.userId);
        if (user == null) throw new NotFoundException("User not found");
        ClientModel client = session.clients().getClientByClientId(realm, spec.clientId);
        if (client == null) throw new NotFoundException("Client not found");

        UserSessionModel userSession = session.sessions().createUserSession(
                realm, user, user.getUsername(), "127.0.0.1", "preview", false, null, null);
        AuthenticatedClientSessionModel clientSession = session.sessions()
                .createClientSession(realm, client, userSession);

        if (spec.userSessionNotes != null) spec.userSessionNotes.forEach(userSession::setNote);
        if (spec.clientSessionNotes != null) spec.clientSessionNotes.forEach(clientSession::setNote);
        if (spec.authTimeEpoch != null) userSession.setNote("auth_time_override", String.valueOf(spec.authTimeEpoch));
        if (spec.acr != null) clientSession.setNote("acr", spec.acr);
        if (spec.amr != null && !spec.amr.isEmpty()) clientSession.setNote("amr", String.join(" ", spec.amr));

        Set<ClientScopeModel> requestedScopes = new LinkedHashSet<>();
        if (Boolean.TRUE.equals(spec.includeDefaultScopes)) client.getClientScopes(true).values().forEach(requestedScopes::add);
        if (Boolean.TRUE.equals(spec.includeOptionalScopes)) client.getClientScopes(false).values().forEach(requestedScopes::add);
        if (spec.addOptionalClientScopes != null) for (String s : spec.addOptionalClientScopes) {
            realm.getClientScopesStream().filter(cs -> Objects.equals(cs.getName(), s)).findFirst().ifPresent(requestedScopes::add);
        }
        if (spec.removeOptionalClientScopes != null) requestedScopes.removeIf(cs -> spec.removeOptionalClientScopes.contains(cs.getName()));
        if (spec.extraClientScopes != null) for (String s : spec.extraClientScopes) {
            realm.getClientScopesStream().filter(cs -> Objects.equals(cs.getName(), s)).findFirst().ifPresent(requestedScopes::add);
        }

        String scopeString = (spec.scopeParam != null) ? spec.scopeParam :
                requestedScopes.stream()
                        .filter(cs -> !(cs instanceof ClientModel))
                        .filter(ClientScopeModel::isIncludeInTokenScope)
                        .map(ClientScopeModel::getName)
                        .collect(Collectors.joining(" "));

        // Build baseline roles directly from the platform
        boolean fullScopeAllowed = client.isFullScopeAllowed();
        Set<RoleModel> baselineRoles = org.keycloak.models.utils.RoleUtils.getDeepUserRoleMappings(user);
        // Scope filter if needed
        if (!fullScopeAllowed) {
            Set<RoleModel> scopeRoles = new HashSet<>();
            requestedScopes.forEach(cs -> cs.getScopeMappingsStream().forEach(scopeRoles::add));
            baselineRoles.removeIf(r -> r.isClientRole() && !scopeRoles.contains(r));
        }
        ClientSessionContext ctx =
                DefaultClientSessionContext.fromClientSessionAndRequestedScopes(clientSession, requestedScopes, session);
        AccessToken baselineToken = new org.keycloak.protocol.oidc.TokenManager()
                .createClientAccessToken(session, realm, client, user, userSession, baselineCtx);
        PolicyLinker.attachPolicies(session, realm, baselineRoles, baselineToken);

        // Preview overlay user: we reuse real user but compute overlay roles
        Set<RoleModel> previewRoles = PreviewRoleComputer.computeEffectiveRoles(
                session, realm, user, client, requestedScopes.stream(), fullScopeAllowed,
                spec.addUserRoles, spec.removeUserRoles, spec.addToComposite,
                Collections.emptyMap(), spec.addGroups, spec.removeGroups);

        ClientSessionContext ctx =
                DefaultClientSessionContext.fromClientSessionAndRequestedScopes(clientSession, requestedScopes, session);
        AccessToken previewToken = new org.keycloak.protocol.oidc.TokenManager()
                .createClientAccessToken(session, realm, client, user, userSession, previewCtx);
        PolicyLinker.attachPolicies(session, realm, previewRoles, previewToken);

        String baselineJson = org.keycloak.util.JsonSerialization.writeValueAsString(baselineToken);
        String previewJson = org.keycloak.util.JsonSerialization.writeValueAsString(previewToken);
        Map<String,Object> diff = TokenDiffUtil.diffTokens(
                org.keycloak.util.JsonSerialization.readValue(baselineJson, Map.class),
                org.keycloak.util.JsonSerialization.readValue(previewJson, Map.class));

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        TokenPreviewEntity e = new TokenPreviewEntity();
        e.id = java.util.UUID.randomUUID().toString();
        e.realmId = realm.getId();
        e.userId = spec.userId;
        e.clientId = spec.clientId;
        e.createdAt = OffsetDateTime.now();
        e.specJson = org.keycloak.util.JsonSerialization.writeValueAsString(spec);
        e.baselineJson = baselineJson;
        e.previewJson = previewJson;
        e.diffJson = org.keycloak.util.JsonSerialization.writeValueAsString(diff);
        em.persist(e);

        Map<String,Object> resp = new LinkedHashMap<>();
        resp.put("id", e.id);
        resp.put("createdAt", e.createdAt.toString());
        resp.put("baselineToken", org.keycloak.util.JsonSerialization.readValue(baselineJson, Object.class));
        resp.put("previewToken", org.keycloak.util.JsonSerialization.readValue(previewJson, Object.class));
        resp.put("diff", diff);
        resp.put("activeRev", activeRev);
        return Response.ok(resp).build();
    }

    @POST @Path("/bundle") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response createBundle(TokenPreviewBundleSpec bundleSpec) {
        RealmModel r = realm();
        if (bundleSpec == null || bundleSpec.items == null || bundleSpec.items.isEmpty())
            throw new BadRequestException("items required");

        RevisionService rs = new RevisionService(session);
        long activeRev = rs.getActiveRev(r);
        if (bundleSpec.expectedActiveRev != null && bundleSpec.expectedActiveRev.longValue() != activeRev)
            throw new ClientErrorException("Active context revision mismatch", 409);

        PreviewBundleConsolidator.ConsolidationResult cr = PreviewBundleConsolidator.consolidate(bundleSpec.items);
        List<String> createdIds = new ArrayList<>();
        for (TokenPreviewSpec s : cr.mergedSpecs) { s.expectedActiveRev = activeRev; Map out = (Map) createPreview(s).getEntity(); createdIds.add((String) out.get("id")); }
        for (TokenPreviewSpec s : cr.standaloneSpecs){ s.expectedActiveRev = activeRev; Map out = (Map) createPreview(s).getEntity(); createdIds.add((String) out.get("id")); }

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        TokenPreviewBundleEntity be = new TokenPreviewBundleEntity();
        be.id = java.util.UUID.randomUUID().toString();
        be.realmId = r.getId();
        be.createdAt = OffsetDateTime.now();
        be.igaMode = (isTidePresent() ? "TIDE-IGA" : "BASIC-IGA");
        be.itemCount = bundleSpec.items.size();
        be.mergedCount = cr.mergedSpecs.size();
        be.standaloneCount = cr.standaloneSpecs.size();
        try {
            be.itemsJson = org.keycloak.util.JsonSerialization.writeValueAsString(bundleSpec.items);
            List<Map<String,Object>> mergedAsMaps = new ArrayList<>();
            for (var s : cr.mergedSpecs) {
                mergedAsMaps.add(org.keycloak.util.JsonSerialization.readValue(org.keycloak.util.JsonSerialization.writeValueAsString(s), Map.class));
            }
            be.mergedJson = org.keycloak.util.JsonSerialization.writeValueAsString(mergedAsMaps);
            be.previewIdsJson = org.keycloak.util.JsonSerialization.writeValueAsString(createdIds);
            be.conflictsJson = org.keycloak.util.JsonSerialization.writeValueAsString(cr.conflicts);
        } catch (Exception ex) { throw new InternalServerErrorException(ex); }
        em.persist(be);

        Map<String,Object> resp = new LinkedHashMap<>();
        resp.put("bundleId", be.id);
        resp.put("igaMode", be.igaMode);
        resp.put("itemCount", be.itemCount);
        resp.put("mergedCount", be.mergedCount);
        resp.put("standaloneCount", be.standaloneCount);
        resp.put("previewIds", createdIds);
        resp.put("conflicts", cr.conflicts);
        resp.put("activeRev", activeRev);
        return Response.ok(resp).build();
    }

    private boolean isTidePresent() {
        try {
            Class.forName("org.tidecloak.tide.iga.ChangeSetSigner.TideIGASigner");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
