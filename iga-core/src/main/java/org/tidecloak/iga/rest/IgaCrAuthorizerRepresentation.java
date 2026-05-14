package org.tidecloak.iga.rest;

/**
 * Tiny DTO describing one admin who has signed a change request: their
 * username and the moment (epoch millis) when the signature was recorded.
 *
 * <p>Distinct from {@link IgaAuthorizerRepresentation}, which represents an
 * entry in the realm-wide authorizer (signer) registry (provider/type/
 * certificate). This DTO is per-change-request, derived from
 * {@code IgaAuthorizationEntity} rows.</p>
 */
public class IgaCrAuthorizerRepresentation {

    private String username;
    private long timestamp;

    public IgaCrAuthorizerRepresentation() {
    }

    public IgaCrAuthorizerRepresentation(String username, long timestamp) {
        this.username = username;
        this.timestamp = timestamp;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
}
