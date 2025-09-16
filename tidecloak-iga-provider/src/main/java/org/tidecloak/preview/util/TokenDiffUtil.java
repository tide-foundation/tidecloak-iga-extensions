// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.util;

import java.util.*;

public class TokenDiffUtil {
    public static List<Map<String,Object>> diffTokens(Map<String,Object> a, Map<String,Object> b){
        List<Map<String,Object>> out = new ArrayList<>();
        Set<String> keys = new TreeSet<>();
        keys.addAll(a.keySet());
        keys.addAll(b.keySet());
        for(String k: keys){
            Object av = a.get(k);
            Object bv = b.get(k);
            if(!Objects.equals(av, bv)){
                Map<String,Object> d = new LinkedHashMap<>();
                d.put("claim", k);
                d.put("from", av);
                d.put("to", bv);
                out.add(d);
            }
        }
        return out;
    }
}
