using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ork.Forseti.Sdk;

namespace Ork.Forseti.Builtins
{
    /// <summary>
    /// Server-verified policy (VM does structure/semantics only).
    /// Inputs via claims (emitted by your gate):
    ///   - cfg.json, cfg.hash (sha256:<hex>)  ← compiled/attested rule config
    ///   - request.id, request.oldIds         ← sign model id + optional legacy ids (JSON array)
    ///   - user                               ← caller's claims (for roles)
    ///   - authorizers.json                   ← server-built list of admin contexts (see TryParseAuthorizers)
    /// Optional AP-payload fallbacks (if cfg leaves blank):
    ///   - ap.signmodels (JSON array)
    ///   - ap.threshold  (string int)
    ///   - vendorId, resource (strings)
    /// </summary>
    public sealed class AuthorizerTemplatePolicy : IAccessPolicy
    {
        public PolicyDecision Authorize(AccessContext ctx)
        {
            ForsetiSdk.SetCultureInvariant();

            // --- 1) fetch and bind config ---
            var cfgJson = ForsetiSdk.Claim("cfg.json");
            var cfgHash = ForsetiSdk.Claim("cfg.hash");
            if (string.IsNullOrWhiteSpace(cfgJson) || string.IsNullOrWhiteSpace(cfgHash))
                return Deny("missing config");

            var computed = "sha256:" + Sha256Hex(cfgJson);
            if (!cfgHash.Equals(computed, StringComparison.OrdinalIgnoreCase))
                return Deny("config hash mismatch");

            if (!TryParseConfig(cfgJson, out var cfg, out var cfgErr))
                return Deny("bad config: " + cfgErr);

            if (!Eq(cfg.vn, "2")) return Deny("unsupported config version");
            if (!Eq(cfg.policy, "AdminAuthTemplate")) return Deny("wrong policy");

            // --- 2) resolve signmodels + threshold (cfg first, then AP fallbacks) ---
            var allowed = (cfg.signmodels is { Length: > 0 })
                ? cfg.signmodels
                : (TryParseStringArray(ForsetiSdk.Claim("ap.signmodels"), out var apSM) ? apSM : Array.Empty<string>());

            var needThreshold = cfg.threshold > 0
                ? cfg.threshold
                : (int.TryParse(ForsetiSdk.Claim("ap.threshold"), out var apThr) ? apThr : 0);

            if (needThreshold < 0) needThreshold = 0; // normalize

            // --- 3) signmodel allow-list check ---
            var reqId   = ForsetiSdk.Claim("request.id") ?? "";
            var allowedHit = Contains(allowed, reqId);
            if (!allowedHit && cfg.allowOldIds)
            {
                allowedHit = TryParseStringArray(ForsetiSdk.Claim("request.oldIds"), out var older)
                             && older.Any(id => Contains(allowed, id));
            }
            if (!allowedHit) return Deny("request not allowed by signmodels");

            // --- 4) role gating (any/all) ---
            var requiredRoles = cfg.requiredRoles ?? Array.Empty<string>();
            if (requiredRoles.Length > 0)
            {
                var have = ExtractRoles(ForsetiSdk.Claim("user") ?? "{}",
                                        cfg.caseInsensitiveRoles ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
                bool ok = cfg.roleMode == "any"
                          ? requiredRoles.Any(have.Contains)
                          : requiredRoles.All(have.Contains);
                if (!ok) return Deny("missing required role(s)");
            }

            // --- 5) admins supplied by the server gate (already signature-verified there) ---
            var authorizersJson = ForsetiSdk.Claim("authorizers.json");
            if (string.IsNullOrWhiteSpace(authorizersJson))
                return Deny("missing authorizers");

            if (!TryParseAuthorizers(authorizersJson, cfgHash, cfg.requireBinding, out var approved, out var aErr))
                return Deny(aErr ?? "invalid authorizers");

            if (approved < needThreshold)
                return Deny($"not enough authorizers {approved}/{needThreshold}");

            // --- 6) optional vendor/resource presence gating ---
            if (cfg.requireVendor && string.IsNullOrEmpty(ForsetiSdk.Claim("vendorId")))
                return Deny("missing vendor");
            if (cfg.requireResource && string.IsNullOrEmpty(ForsetiSdk.Claim("resource")))
                return Deny("missing resource");

            return PolicyDecision.Allow();
        }

        /* ================= helpers ================= */

        private static bool Eq(string? a, string b) => string.Equals(a, b, StringComparison.Ordinal);
        private static bool Contains(string[] arr, string s) => Array.IndexOf(arr, s) >= 0;
        private static PolicyDecision Deny(string reason) => PolicyDecision.Deny(reason);

        private static string Sha256Hex(string s)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private sealed class RuleConfigDto
        {
            public string vn { get; set; } = "2";
            public string policy { get; set; } = "AdminAuthTemplate";
            public int threshold { get; set; } = 0;
            public string[]? requiredRoles { get; set; }
            public string roleMode { get; set; } = "all";     // "all" | "any"
            public string[]? signmodels { get; set; }
            public bool allowOldIds { get; set; } = true;
            public bool requireVendor { get; set; } = false;
            public bool requireResource { get; set; } = false;
            public bool requireBinding { get; set; } = true;  // require policyRef == cfg.hash on each admin
            public bool caseInsensitiveRoles { get; set; } = true;
        }

        private static bool TryParseConfig(string json, out RuleConfigDto cfg, out string err)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var r = doc.RootElement;
                cfg = new RuleConfigDto
                {
                    vn                 = r.TryGetProperty("vn", out var vn) ? (vn.GetString() ?? "2") : "2",
                    policy             = r.TryGetProperty("policy", out var pl) ? (pl.GetString() ?? "AdminAuthTemplate") : "AdminAuthTemplate",
                    threshold          = r.TryGetProperty("threshold", out var th) && th.TryGetInt32(out var t) ? t : 0,
                    requiredRoles      = r.TryGetProperty("requiredRoles", out var rr) && rr.ValueKind == JsonValueKind.Array
                                         ? rr.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                                         : Array.Empty<string>(),
                    roleMode           = r.TryGetProperty("roleMode", out var rm) ? (rm.GetString() ?? "all") : "all",
                    signmodels         = r.TryGetProperty("signmodels", out var sm) && sm.ValueKind == JsonValueKind.Array
                                         ? sm.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                                         : Array.Empty<string>(),
                    allowOldIds        = r.TryGetProperty("allowOldIds", out var ao) && ao.ValueKind == JsonValueKind.True,
                    requireVendor      = r.TryGetProperty("requireVendor", out var rv) && rv.ValueKind == JsonValueKind.True,
                    requireResource    = r.TryGetProperty("requireResource", out var rrq) && rrq.ValueKind == JsonValueKind.True,
                    requireBinding     = r.TryGetProperty("requireBinding", out var rb) && rb.ValueKind == JsonValueKind.True,
                    caseInsensitiveRoles = r.TryGetProperty("caseInsensitiveRoles", out var cir) && cir.ValueKind == JsonValueKind.True,
                };
                err = "";
                return true;
            }
            catch (Exception ex) { cfg = new RuleConfigDto(); err = ex.Message; return false; }
        }

        private static bool TryParseStringArray(string? json, out string[] arr)
        {
            if (string.IsNullOrWhiteSpace(json)) { arr = Array.Empty<string>(); return true; }
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) { arr = Array.Empty<string>(); return false; }
                arr = doc.RootElement.EnumerateArray()
                        .Select(e => e.GetString() ?? "")
                        .Where(s => s.Length > 0)
                        .ToArray();
                return true;
            }
            catch { arr = Array.Empty<string>(); return false; }
        }

        private static HashSet<string> ExtractRoles(string claimsJson, StringComparer cmp)
        {
            var set = new HashSet<string>(cmp);
            try
            {
                using var doc = JsonDocument.Parse(claimsJson);
                var root = doc.RootElement;

                // flat: { "roles": ["a","b"] }
                if (root.TryGetProperty("roles", out var flat) && flat.ValueKind == JsonValueKind.Array)
                    foreach (var r in flat.EnumerateArray())
                        if (r.GetString() is string s && s.Length > 0) set.Add(s);

                // Keycloak-ish: realm_access.roles
                if (root.TryGetProperty("realm_access", out var realm) &&
                    realm.TryGetProperty("roles", out var rr) &&
                    rr.ValueKind == JsonValueKind.Array)
                    foreach (var r in rr.EnumerateArray())
                        if (r.GetString() is string s && s.Length > 0) set.Add(s);

                // resource_access.{client}.roles
                if (root.TryGetProperty("resource_access", out var res) && res.ValueKind == JsonValueKind.Object)
                    foreach (var client in res.EnumerateObject())
                        if (client.Value.TryGetProperty("roles", out var cr) && cr.ValueKind == JsonValueKind.Array)
                            foreach (var r in cr.EnumerateArray())
                                if (r.GetString() is string s && s.Length > 0) set.Add($"{client.Name}:{s}");
            }
            catch { /* swallow → empty set */ }
            return set;
        }

        /// <summary>
        /// Parse server-built admins list and count unique, approved entries.
        /// Enforces uniqueness by tideuserkey, and (optionally) binding via policyRef == cfgHash.
        /// Expected shape per element:
        ///   {
        ///     "tideuserkey": "<base64-ed25519-pub>",
        ///     "approved": true,
        ///     "policyRef": "sha256:<hex(cfg.json)>" // required when requireBinding=true
        ///   }
        /// </summary>
        private static bool TryParseAuthorizers(
            string json, string cfgHash, bool requireBinding,
            out int approved, out string? error)
        {
            approved = 0; error = null;
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Array)
                { error = "authorizers not array"; return false; }

                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    if (el.ValueKind != JsonValueKind.Object) continue;

                    if (!el.TryGetProperty("tideuserkey", out var k) || k.ValueKind != JsonValueKind.String)
                        continue;

                    var key = k.GetString() ?? "";
                    if (key.Length == 0) continue;

                    // uniqueness
                    if (!seen.Add(key)) { error = "duplicate authorizer key"; return false; }

                    // binding to this config (if required)
                    if (requireBinding)
                    {
                        if (!el.TryGetProperty("policyRef", out var pr) || pr.ValueKind != JsonValueKind.String)
                            continue;
                        var refVal = pr.GetString() ?? "";
                        if (!refVal.Equals(cfgHash, StringComparison.OrdinalIgnoreCase))
                            continue;
                    }

                    // server approval flag
                    if (el.TryGetProperty("approved", out var ap) && ap.ValueKind == JsonValueKind.True)
                        approved++;
                }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }
    }
}
