package org.tidecloak.preview.rest;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.util.DefaultClientSessionContext;

import org.tidecloak.preview.authz.PolicyLinker;
import org.tidecloak.jpa.entities.preview.TokenPreviewBundleEntity;
import org.tidecloak.jpa.entities.preview.TokenPreviewEntity;
import org.tidecloak.preview.dto.TokenPreviewBundleSpec;
import org.tidecloak.preview.dto.TokenPreviewSpec;
import org.tidecloak.preview.service.RevisionService;
import org.tidecloak.preview.util.PreviewBundleConsolidator;
import org.tidecloak.preview.util.TokenDiffUtil;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Path("/token-preview")
public class TokenPreviewRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public TokenPreviewRealmResourceProvider(KeycloakSession session) { this.session = session; }

    @Override public Object getResource() { return this; }
    @Override public void close() { }

    private RealmModel realm() { return session.getContext().getRealm(); }

    @POST @Path("/") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response createPreview(TokenPreviewSpec spec) throws IOException {
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
            // Fallback issuer field – realm name; if you want URL, compute from baseUri
            tok.put("iss", realm.getName() != null ? realm.getName() : "");
            tok.put("azp", client.getClientId());

            // Minimal realm_access from default role (if present)
            RoleModel def = realm.getDefaultRole();
            if (def != null) {
                Set<String> rr = new TreeSet<>();
                RoleUtils.expandCompositeRolesStream(java.util.stream.Stream.of(def))
                        .forEach(role -> rr.add(role.getName()));
                if (!rr.isEmpty()) {
                    Map<String,Object> ra = new LinkedHashMap<>();
                    ra.put("roles", new ArrayList<>(rr));
                    tok.put("realm_access", ra);
                }
            }

            Map<String,Object> out = new LinkedHashMap<>();
            out.put("baselineToken", tok);
            out.put("previewToken", tok);
            out.put("diff", List.of()); // list, consistent with TokenDiffUtil
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

        // BASELINE token
        ClientSessionContext baselineCtx =
                DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, scopeString, session);
        AccessToken baselineToken = new TokenManager()
                .createClientAccessToken(session, realm, client, user, userSession, baselineCtx);

        // Apply any policy overlays on baseline (optional)
        PolicyLinker.attachPolicies(session, realm, null, baselineToken);

        // PREVIEW token starts from baseline, then apply deltas
        AccessToken previewToken = org.keycloak.util.JsonSerialization.readValue(
                org.keycloak.util.JsonSerialization.writeValueAsString(baselineToken), AccessToken.class);

        // Mutate roles based on spec (same helpers as regen service)
        RoleDelta delta = RoleDelta.fromSpec(session, realm, spec);
        delta.applyTo(previewToken);

        String baselineJson = org.keycloak.util.JsonSerialization.writeValueAsString(baselineToken);
        String previewJson  = org.keycloak.util.JsonSerialization.writeValueAsString(previewToken);

        @SuppressWarnings("unchecked")
        Map<String,Object> baselineMap = org.keycloak.util.JsonSerialization.readValue(baselineJson, Map.class);
        @SuppressWarnings("unchecked")
        Map<String,Object> previewMap  = org.keycloak.util.JsonSerialization.readValue(previewJson, Map.class);

        // diff is a LIST
        List<Map<String,Object>> diff = TokenDiffUtil.diffTokens(baselineMap, previewMap);

        // persist
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
        resp.put("baselineToken", baselineMap);
        resp.put("previewToken", previewMap);
        resp.put("diff", diff);
        resp.put("activeRev", activeRev);
        return Response.ok(resp).build();
    }

    @POST @Path("/bundle") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response createBundle(TokenPreviewBundleSpec bundleSpec) throws IOException {
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
                mergedAsMaps.add(org.keycloak.util.JsonSerialization.readValue(
                        org.keycloak.util.JsonSerialization.writeValueAsString(s), Map.class));
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

    // ---- helpers reused here ----

    private static final class RoleDelta {
        final Set<String> addRealm = new HashSet<>();
        final Set<String> delRealm = new HashSet<>();
        final Map<String, Set<String>> addClient = new HashMap<>();
        final Map<String, Set<String>> delClient = new HashMap<>();

        static RoleDelta fromSpec(KeycloakSession session, RealmModel realm, TokenPreviewSpec spec) {
            RoleDelta d = new RoleDelta();

            // user role adds/removes
            collectRoles(session, realm, spec.addUserRoles, d.addRealm, d.addClient, true);
            collectRoles(session, realm, spec.removeUserRoles, d.delRealm, d.delClient, true);

            // group adds/removes (expand composites)
            if (spec.addGroups != null) {
                for (String gref : spec.addGroups) {
                    GroupModel g = resolveGroup(session, realm, gref);
                    if (g != null) expandAndBucket(g.getRoleMappingsStream(), realm, d.addRealm, d.addClient);
                }
            }
            if (spec.removeGroups != null) {
                for (String gref : spec.removeGroups) {
                    GroupModel g = resolveGroup(session, realm, gref);
                    if (g != null) expandAndBucket(g.getRoleMappingsStream(), realm, d.delRealm, d.delClient);
                }
            }
            return d;
        }

        void applyTo(AccessToken token) {
            AccessToken.Access ra = token.getRealmAccess();
            if (ra == null) { ra = new AccessToken.Access(); token.setRealmAccess(ra); }
            if (!addRealm.isEmpty()) ra.getRoles().addAll(addRealm);
            if (!delRealm.isEmpty()) ra.getRoles().removeAll(delRealm);

            Map<String, AccessToken.Access> res = token.getResourceAccess();
            if (res == null) { res = new LinkedHashMap<>(); token.setResourceAccess(res); }

            Map<String, AccessToken.Access> finalRes = res;
            addClient.forEach((cid, roles) -> finalRes.computeIfAbsent(cid, __ -> new AccessToken.Access()).getRoles().addAll(roles));
            delClient.forEach((cid, roles) -> {
                AccessToken.Access a = finalRes.get(cid);
                if (a != null) a.getRoles().removeAll(roles);
            });
        }

        private static void collectRoles(KeycloakSession session, RealmModel realm, Collection<?> refs,
                                         Set<String> outRealm, Map<String, Set<String>> outClient, boolean expand) {
            if (refs == null) return;
            for (Object rr : refs) {
                RoleModel r = resolveRole(session, realm, rr);
                if (r == null) continue;
                if (expand) {
                    RoleUtils.expandCompositeRolesStream(Stream.of(r)).forEach(x -> bucket(x, realm, outRealm, outClient));
                } else {
                    bucket(r, realm, outRealm, outClient);
                }
            }
        }

        private static void expandAndBucket(Stream<RoleModel> roles, RealmModel realm,
                                            Set<String> outRealm, Map<String, Set<String>> outClient) {
            RoleUtils.expandCompositeRolesStream(roles).forEach(r -> bucket(r, realm, outRealm, outClient));
        }

        private static void bucket(RoleModel r, RealmModel realm,
                                   Set<String> outRealm, Map<String, Set<String>> outClient) {
            if (r.isClientRole()) {
                ClientModel c = realm.getClientById(r.getContainerId());
                if (c != null) outClient.computeIfAbsent(c.getClientId(), __ -> new HashSet<>()).add(r.getName());
            } else {
                outRealm.add(r.getName());
            }
        }

        private static RoleModel resolveRole(KeycloakSession session, RealmModel realm, Object ref) {
            if (ref == null) return null;
            String name = null, clientId = null, kind = null;
            try {
                if (ref instanceof String s) {
                    name = s;
                } else if (ref instanceof Map<?,?> m) {
                    Object n = m.get("name"); if (n instanceof String) name = (String) n;
                    Object c = m.get("clientId"); if (c instanceof String) clientId = (String) c;
                    Object k = m.get("kind"); if (k instanceof String) kind = (String) k;
                } else {
                    try { name = (String) ref.getClass().getMethod("getName").invoke(ref); } catch (Exception ignored) {}
                    try { clientId = (String) ref.getClass().getMethod("getClientId").invoke(ref); } catch (Exception ignored) {}
                    try { kind = (String) ref.getClass().getMethod("getKind").invoke(ref); } catch (Exception ignored) {}
                    if (name == null) { try { name = (String) ref.getClass().getField("name").get(ref); } catch (Exception ignored) {} }
                    if (clientId == null) { try { clientId = (String) ref.getClass().getField("clientId").get(ref); } catch (Exception ignored) {} }
                    if (kind == null) { try { kind = (String) ref.getClass().getField("kind").get(ref); } catch (Exception ignored) {} }
                }
            } catch (Throwable ignored) {}
            RoleModel r;
            if ("realm".equalsIgnoreCase(kind) && name != null) {
                r = realm.getRole(name);
                if (r != null) return r;
            }
            if (clientId != null && name != null) {
                ClientModel c = session.clients().getClientByClientId(realm, clientId);
                if (c != null) {
                    r = c.getRole(name);
                    if (r != null) return r;
                }
            }
            if (name != null) {
                r = realm.getRole(name);
                if (r != null) return r;
                for (ClientModel c : realm.getClientsStream().toList()) {
                    r = c.getRole(name);
                    if (r != null) return r;
                }
            }
            return null;
        }

        private static GroupModel resolveGroup(KeycloakSession session, RealmModel realm, String ref) {
            if (ref == null) return null;
            GroupModel g = KeycloakModelUtils.findGroupByPath(session, realm, ref);
            if (g != null) return g;
            for (GroupModel gm : realm.getGroupsStream().toList()) {
                if (ref.equals(gm.getName())) return gm;
            }
            return null;
        }
    }
}
