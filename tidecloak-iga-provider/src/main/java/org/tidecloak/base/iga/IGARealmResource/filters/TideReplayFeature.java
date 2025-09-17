package org.tidecloak.base.iga.IGARealmResource.filters;

import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.FeatureContext;
public class TideReplayFeature implements Feature {
    @Override
    boolean configure(FeatureContext context) {
        context.register(ReplayEnforcementFilter.class);
        return true;
    }
}
