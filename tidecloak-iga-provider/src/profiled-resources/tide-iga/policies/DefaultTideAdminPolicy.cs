#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Ork.Forseti.Sdk;

namespace Ork.Forseti.Builtins
{
	public sealed class AuthorizerTemplatePolicy : IAccessPolicy
	{
		public PolicyDecision Authorize(AccessContext ctx)
		{
			ForsetiSdk.SetCultureInvariant();

			var stage      = ForsetiSdk.Claim("stage") ?? "auth";         // "auth" | "sign"
			var requestId  = ForsetiSdk.Claim("request.id") ?? "";        // e.g. "Admin:2" or "UserContext:1"
			var stageKey   = $"{stage}:{requestId}";
			var cfgHash    = ForsetiSdk.Claim("cfg.hash") ?? "";          // sha512:...
			var cfgJson    = ForsetiSdk.Claim("cfg.json") ?? "";          // attested config
			if (string.IsNullOrEmpty(cfgHash) || string.IsNullOrEmpty(cfgJson))
				return PolicyDecision.Deny("missing cfg");

			// parse config
			if (!TryParseConfig(cfgJson, out var cfg, out var cfgErr))
				return PolicyDecision.Deny("bad cfg: " + cfgErr);
			if (!Eq(cfg.vn, "2")) return PolicyDecision.Deny("unsupported cfg vn");
			if (!Eq(cfg.policy, "AdminAuthTemplate")) return PolicyDecision.Deny("wrong policy");

			// signmodel allow-list
			var reqModel = ForsetiSdk.Claim("request.id") ?? "";
			var allowed = cfg.signmodels ?? Array.Empty<string>();
			if (!allowed.Contains(reqModel) && !(cfg.allowOldIds && TryContainsAny(ForsetiSdk.Claim("request.oldIds"), allowed)))
				return PolicyDecision.Deny("signmodel not allowed");

			// authorizers: only those contexts that have policyRefs[stageKey] containing cfg.hash
			var authorizersJson = ForsetiSdk.Claim("authorizers.json");
			if (string.IsNullOrWhiteSpace(authorizersJson))
				return PolicyDecision.Deny("missing authorizers");

			if (!TryCountStageApproved(authorizersJson, stageKey, cfgHash, out int approved, out var err))
				return PolicyDecision.Deny(err ?? "authorizers invalid");
			if (approved < cfg.threshold)
				return PolicyDecision.Deny($"not enough authorizers {approved}/{cfg.threshold}");

			// optional vendor/resource checks
			if (cfg.requireVendor && string.IsNullOrEmpty(ForsetiSdk.Claim("vendorId")))
				return PolicyDecision.Deny("missing vendor");
			if (cfg.requireResource && string.IsNullOrEmpty(ForsetiSdk.Claim("resource")))
				return PolicyDecision.Deny("missing resource");

			return PolicyDecision.Allow();
		}

		private sealed class RuleConfigDto {
			public string vn { get; set; } = "2";
			public string policy { get; set; } = "AdminAuthTemplate";
			public int threshold { get; set; }
			public string[]? signmodels { get; set; }
			public bool allowOldIds { get; set; }
			public bool requireVendor { get; set; }
			public bool requireResource { get; set; }
		}

		private static bool Eq(string? a, string b) => string.Equals(a, b, StringComparison.Ordinal);
		private static bool TryContainsAny(string? jsonArr, string[] allowed)
		{
			if (string.IsNullOrEmpty(jsonArr)) return false;
			try {
				using var d = JsonDocument.Parse(jsonArr);
				if (d.RootElement.ValueKind != JsonValueKind.Array) return false;
				var set = new HashSet<string>(allowed, StringComparer.Ordinal);
				foreach (var e in d.RootElement.EnumerateArray())
					if (e.ValueKind == JsonValueKind.String && set.Contains(e.GetString() ?? "")) return true;
			} catch { }
			return false;
		}

		private static bool TryParseConfig(string json, out RuleConfigDto cfg, out string? err)
		{
			try {
				using var d = JsonDocument.Parse(json);
				var r = d.RootElement;
				cfg = new RuleConfigDto {
					vn = r.GetProperty("vn").GetString() ?? "2",
					policy = r.GetProperty("policy").GetString() ?? "AdminAuthTemplate",
					threshold = r.GetProperty("threshold").GetInt32(),
					signmodels = r.TryGetProperty("signmodels", out var sm) && sm.ValueKind == JsonValueKind.Array
						? sm.EnumerateArray().Select(x => x.GetString() ?? "").Where(s => s.Length > 0).ToArray()
						: Array.Empty<string>(),
					allowOldIds = r.TryGetProperty("allowOldIds", out var ao) && ao.GetBoolean(),
					requireVendor = r.TryGetProperty("requireVendor", out var rv) && rv.GetBoolean(),
					requireResource = r.TryGetProperty("requireResource", out var rr) && rr.GetBoolean(),
				};
				err = null; return true;
			} catch (Exception ex) { cfg = new RuleConfigDto(); err = ex.Message; return false; }
		}

		private static bool TryCountStageApproved(string json, string stageKey, string cfgHash, out int approved, out string? err)
		{
			approved = 0; err = null;
			try {
				using var d = JsonDocument.Parse(json);
				if (d.RootElement.ValueKind != JsonValueKind.Array) { err = "authorizers not array"; return false; }
				var seen = new HashSet<string>(StringComparer.Ordinal);
				foreach (var el in d.RootElement.EnumerateArray())
				{
					if (el.ValueKind != JsonValueKind.Object) continue;
					if (!el.TryGetProperty("tideuserkey", out var k) || k.ValueKind != JsonValueKind.String) continue;
					var key = k.GetString() ?? ""; if (key.Length == 0) continue;
					if (!seen.Add(key)) { err = "duplicate authorizer key"; return false; }

					// policyRefs[stageKey] must contain cfgHash
					if (!el.TryGetProperty("policyRefs", out var refs) || refs.ValueKind != JsonValueKind.Object) continue;
					if (!refs.TryGetProperty(stageKey, out var arr) || arr.ValueKind != JsonValueKind.Array) continue;

					var ok = arr.EnumerateArray().Any(v => v.ValueKind == JsonValueKind.String &&
						string.Equals(v.GetString(), cfgHash, StringComparison.Ordinal));
					if (ok) approved++;
				}
				return true;
			} catch (Exception ex) { err = ex.Message; return false; }
		}
	}
}
