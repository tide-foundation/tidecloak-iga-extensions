// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.dto;

import java.util.List;
import java.util.Map;


public class TokenPreviewSpec {
    public String userId;           // user for preview
    public String clientId;         // target clientId
    public Boolean defaultClientContext; // if true, userId is ignored and a userless preview for client is returned

    // Consistency
    public Long expectedActiveRev;

    // Scope controls
    public Boolean includeDefaultScopes;
    public Boolean includeOptionalScopes;
    public List<String> addOptionalClientScopes;
    public List<String> removeOptionalClientScopes;
    public List<String> extraClientScopes;
    public String scopeParam;

    public Boolean overrideFullScopeAllowed; // preview-only override full-scope

    // Session overrides
    public Map<String,String> userSessionNotes;
    public Map<String,String> clientSessionNotes;
    public Long authTimeEpoch;
    public String acr;
    public List<String> amr;

    // Realm / Client attribute overlays (temporary for the preview only)
    public Map<String,String> realmAttributes;
    public Map<String,String> clientAttributes;

    // User attribute patches (preview-only)
    public List<AttrPatch> userAttributePatches;
    public static class AttrPatch {
        public String key;
        public List<String> values;
    }

    // Preview deltas
    public List<String> addGroups;     // group paths or names
    public List<String> removeGroups;
    public List<RoleRef> addUserRoles; // roleName + clientId (null for realm roles)
    public List<RoleRef> removeUserRoles;

    // Composite deltas (if user has composite, add/remove child roles)
    public List<CompositeRef> addToComposite;
    public List<CompositeRef> removeFromComposite;

    // Group role link deltas (attach group role, mostly used for previews)
    public List<GroupRoleRef> addGroupLinks;
    public List<GroupRoleRef> removeGroupLinks;

    public static class RoleRef {
        public String roleName;
        public String clientId; // null for realm role
    }
    public static class CompositeRef {
        public String compositeRoleName;
        public String compositeClientId; // null for realm role
        public String childRoleName;
        public String childClientId; // null for realm role
    }
    public static class GroupRoleRef {
        public String group; // path or name
        public String roleName;
        public String clientId; // null for realm role
    }
}
