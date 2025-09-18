package org.tidecloak.base.iga.IGARealmResource.filters;

import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.FeatureContext;

/**
 * Registers the auto-draft (rewrite) and enforcement filters.
 * Keep exactly one service entry:
 *   META-INF/services/jakarta.ws.rs.core.Feature
 *     -> org.tidecloak.base.iga.IGARealmResource.filters.TideReplayFeature
 */
public class TideReplayFeature implements Feature {
    @Override
    public boolean configure(FeatureContext context) {
        context.register(ReplayAutoDraftFilter.class);   // PreMatching, rewrites into /tide/replay
        context.register(ReplayEnforcementFilter.class); // Authorization, blocks direct mutations
        return true;
    }
}
