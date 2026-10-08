package org.tidecloak.iga.rest;

import org.keycloak.cluster.ClusterProvider;
import org.keycloak.cluster.ExecutionResult;
import org.keycloak.models.KeycloakSession;

import java.util.concurrent.Callable;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * Stubs the per-realm {@link IgaBulkLock} cluster mutex so its callable runs INLINE.
 *
 * <p>Both the bulk lane and the single-CR commit pipeline acquire the lock, so any test that
 * drives {@code bulkAuthorize}, {@code commit} or {@code approve} needs the
 * {@link ClusterProvider} to resolve or the resource throws before reaching the behaviour
 * under test.
 */
final class IgaTestClusterLock {

    private IgaTestClusterLock() {
    }

    @SuppressWarnings("unchecked")
    static void stubInlineClusterLock(KeycloakSession session) {
        ClusterProvider cluster = mock(ClusterProvider.class);
        lenient().when(session.getProvider(ClusterProvider.class)).thenReturn(cluster);
        lenient().when(cluster.executeIfNotExecuted(anyString(), anyInt(), any(Callable.class)))
                .thenAnswer(inv -> ExecutionResult.executed(
                        ((Callable<Object>) inv.getArgument(2)).call()));
    }
}
