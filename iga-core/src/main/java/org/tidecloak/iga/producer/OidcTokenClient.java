package org.tidecloak.iga.producer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fetches a REAL issued token from the realm's OIDC token endpoint via a
 * Resource-Owner-Password-Credentials (ROPC / {@code password}) grant — the
 * proven path from the design §8 ("there is no clean in-process mint API from
 * iga-core; {@code DefaultTokenManager.encode} needs a full protocol request
 * context"). The producer talks plain HTTP to
 * {@code /realms/{realm}/protocol/openid-connect/token}; the issued
 * {@code access_token} is a real compact JWS (header.payload.signature).
 *
 * <p>The four {@code TokenRequest} fields the ork needs are NOT recovered from
 * the token — they are the grant parameters this client issues, captured by the
 * caller into the {@link ExportRequest}. This client only obtains the token
 * bytes.
 */
public final class OidcTokenClient {

    private static final Logger log = Logger.getLogger(OidcTokenClient.class);

    private final String baseUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param baseUrl the Keycloak base URL WITHOUT trailing slash, e.g.
     *                {@code http://localhost:8080}. The realm path is appended.
     */
    public OidcTokenClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** The result of a token fetch: the compact JWS access token plus raw JSON. */
    public record TokenResponse(String accessToken, String idToken, JsonNode raw) {
    }

    /**
     * ROPC password grant. The {@code clientId} must have direct-access-grants
     * enabled. {@code scope} may be {@code null} (omits the scope param → client
     * defaults). Returns the parsed token response; throws on a non-2xx.
     *
     * @param realmName the realm NAME (the path segment), not its UUID.
     */
    public TokenResponse passwordGrant(String realmName, String clientId,
                                       String clientSecret, String username,
                                       String password, String scope) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "password");
        form.put("client_id", clientId);
        if (clientSecret != null && !clientSecret.isEmpty()) {
            form.put("client_secret", clientSecret);
        }
        form.put("username", username);
        form.put("password", password);
        if (scope != null && !scope.isEmpty()) {
            form.put("scope", scope);
        }

        String url = baseUrl + "/realms/" + encodePath(realmName)
                + "/protocol/openid-connect/token";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build();

        try {
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                throw new IllegalStateException(
                        "token endpoint returned " + resp.statusCode() + ": " + resp.body());
            }
            JsonNode body = mapper.readTree(resp.body());
            JsonNode at = body.get("access_token");
            if (at == null || at.asText().isEmpty()) {
                throw new IllegalStateException("token response has no access_token: " + resp.body());
            }
            String accessToken = at.asText();
            String idToken = body.hasNonNull("id_token") ? body.get("id_token").asText() : null;
            if (accessToken.split("\\.").length != 3) {
                log.warnf("access_token is not a 3-segment compact JWS (segments=%d)",
                        accessToken.split("\\.").length);
            }
            return new TokenResponse(accessToken, idToken, body);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("OIDC token fetch failed: " + e.getMessage(), e);
        }
    }

    private static String formEncode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private static String encodePath(String segment) {
        // Realm names are restricted to a safe charset by KC; encode spaces etc.
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
