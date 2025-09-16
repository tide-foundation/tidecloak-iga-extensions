// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.util;

import org.tidecloak.preview.dto.TokenPreviewSpec;
import java.util.*;

public class PreviewBundleConsolidator {

    public static class ConsolidationResult {
        public List<TokenPreviewSpec> mergedSpecs = new ArrayList<>();
        public List<TokenPreviewSpec> standaloneSpecs = new ArrayList<>();
        public List<Map<String,Object>> conflicts = new ArrayList<>();
    }

    /**
     * Merge preview specs by (userId,clientId). If same pair appears multiple times, combine list fields.
     * Default-client contexts are never merged with normal specs.
     */
    public static ConsolidationResult consolidate(List<TokenPreviewSpec> items){
        ConsolidationResult cr = new ConsolidationResult();
        if(items == null || items.isEmpty()) return cr;

        Map<String, TokenPreviewSpec> merged = new LinkedHashMap<>();
        for(TokenPreviewSpec s: items){
            if(Boolean.TRUE.equals(s.defaultClientContext)){
                cr.standaloneSpecs.add(s);
                continue;
            }
            String k = (s.userId == null ? "null" : s.userId) + "||" + (s.clientId == null ? "null" : s.clientId);
            if(!merged.containsKey(k)){
                merged.put(k, s);
            } else {
                TokenPreviewSpec base = merged.get(k);
                base.addGroups = join(base.addGroups, s.addGroups);
                base.removeGroups = join(base.removeGroups, s.removeGroups);
                base.addUserRoles = join(base.addUserRoles, s.addUserRoles);
                base.removeUserRoles = join(base.removeUserRoles, s.removeUserRoles);
                base.addToComposite = join(base.addToComposite, s.addToComposite);
                base.removeFromComposite = join(base.removeFromComposite, s.removeFromComposite);
                base.addGroupLinks = join(base.addGroupLinks, s.addGroupLinks);
                base.removeGroupLinks = join(base.removeGroupLinks, s.removeGroupLinks);
            }
        }
        cr.mergedSpecs.addAll(merged.values());
        return cr;
    }

    private static <T> List<T> join(List<T> a, List<T> b){
        if(a == null) return b;
        if(b == null) return a;
        List<T> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }
}
