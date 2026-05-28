package org.tidecloak.iga.producer;

/**
 * The token surface the bundle is validated against. Wire value goes into the
 * bundle's {@code request.t} field — the ork {@code TokenRequest.TokenType}
 * distinguishes {@code access} vs {@code id} so the verifier applies the right
 * per-mapper claim gate ({@code access.token.claim} vs {@code id.token.claim}).
 *
 * <p>The wire strings are exactly {@code "access"} / {@code "id"} (the bundle
 * format §request.t locks {@code "access|id"}).
 */
public enum TokenType {
    access,
    id
}
