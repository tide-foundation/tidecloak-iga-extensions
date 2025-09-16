// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.service;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Revision number lives in realm attribute 'activeContextRevision'. */
public class RevisionService {
    private final KeycloakSession session;
    public RevisionService(KeycloakSession s){ this.session = s; }

    public long getActiveRev(RealmModel realm){
        try {
            String v = realm.getAttribute("activeContextRevision");
            if(v == null || v.isBlank()) return 0L;
            return Long.parseLong(v);
        } catch (Exception e){
            return 0L;
        }
    }

    public long bumpActiveRev(RealmModel realm){
        long cur = getActiveRev(realm);
        long next = cur + 1L;
        realm.setAttribute("activeContextRevision", Long.toString(next));
        return next;
    }
}
