package org.tidecloak.iga.services;

/**
 * Detects whether the current thread is executing inside Keycloak's own
 * model-version migration (the {@code MigrationModelManager} /
 * {@code org.keycloak.migration.migrators.*} chain that runs on boot when the
 * stored model version is older than the server's, and on realm-import version
 * upgrades).
 *
 * <h2>Why this exists</h2>
 * Keycloak's migrations write to realms/clients/client-scopes/roles through the
 * normal model layer — {@code session.realms()}, {@code realm.getClientScopesStream()},
 * {@code role.addCompositeRole(...)}, {@code session.clients().addClientScopeToAllClients(...)}
 * etc. Those calls resolve to the IGA-wrapped providers/adapters (they win at
 * factory {@code order() == 2}). Without a guard, an IGA-enabled realm that
 * happens to carry a <em>pending</em> change request has every migration write
 * captured by the IGA interceptor, and — because a foreign pending CR is a
 * conflict — the capture path throws {@link org.tidecloak.iga.providers.IgaConflictException}.
 *
 * <p>At migration time there is no JAX-RS exception mapper, so that exception
 * propagates uncaught out of the single {@code runJobInTransaction} that wraps
 * both the migration and the stored-version bump. The transaction rolls back
 * (version never advances) and the server fails to boot — and, because the
 * version is not advanced, re-fails identically on every subsequent restart.
 * This surfaced on the 26.7.0 upgrade, whose migration writes to every realm
 * (new SAML {@code AuthnContextClassRef} scope, {@code admin-permissions}
 * client, org admin roles, parameterized-scope attribute renames).</p>
 *
 * <h2>Semantics</h2>
 * A Keycloak model migration is a mechanical, system-authored schema/config
 * upgrade — <em>not</em> an admin-authored change for a governance approver to
 * vote on. Its writes must apply directly to the model (fall through to
 * {@code super.*}), exactly like replay ({@code IGA_REPLAY_ACTIVE}) and vendor
 * provisioning ({@code IGA_VENDOR_PROVISIONING}). This helper is the third such
 * "apply directly, never capture" signal; every {@code isIgaActive()} chokepoint
 * consults it alongside the other two.
 *
 * <h2>Why a StackWalker (and not a session flag)</h2>
 * The migration entry point lives in Keycloak core (the fork), so there is no
 * iga-core-owned seam at which to set a session attribute around it. A
 * thread-stack probe is self-contained in iga-core, needs no fork change, is
 * immune to session-identity concerns, and matches the existing idiom already
 * used in {@code IgaRealmAdapter.isOnRealmBootstrapPath()} /
 * {@code IgaRealmProvider.isOnClientCreationPath()} /
 * {@code IgaUserAdapter.computeImmediateCaller()}.
 *
 * <h2>No false positives on the normal request path</h2>
 * The matched frames appear ONLY while a model-version migration is executing
 * ({@code QuarkusJpaConnectionProviderFactory.migrateModel} at boot, or
 * {@code MigrationModelManager.migrateImport} during a realm-rep import). A
 * normal admin REST write (JAX-RS resource -> model provider) never traverses
 * the {@code org.keycloak.migration.*} packages, so ongoing admin edits stay
 * governed. The import-time migration case is correctly suppressed too — it is
 * the same class of system-authored upgrade.
 */
public final class IgaMigrationContext {

    /** Package prefix carrying every concrete migrator ({@code MigrateTo26_7_0},
     *  {@code RealmMigration}, {@code MigrationUtils}, …). A migrator's own frame
     *  ({@code migrateRealm} and its private helpers) is always on the stack
     *  below any governed write it triggers, so matching the prefix ANYWHERE on
     *  the stack catches writes that fan out through helper classes
     *  (e.g. {@code AdminPermissionsSchema.init}, {@code addClientScopeToAllClients})
     *  too. */
    private static final String MIGRATORS_PACKAGE_PREFIX = "org.keycloak.migration.migrators.";

    /** The migration transaction entry point — guaranteed present below every
     *  migrator frame. Matched as belt-and-braces so the guard still holds if a
     *  future migrator were to run a write without keeping its own frame on the
     *  stack. */
    private static final String MIGRATION_MODEL_MANAGER = "org.keycloak.migration.MigrationModelManager";

    private IgaMigrationContext() {
    }

    /**
     * @return {@code true} iff a Keycloak model-migration frame is present
     *         anywhere on the current thread's call stack.
     */
    public static boolean isOnKeycloakMigrationPath() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f -> {
                    String cn = f.getDeclaringClass().getName();
                    return cn.startsWith(MIGRATORS_PACKAGE_PREFIX)
                            || MIGRATION_MODEL_MANAGER.equals(cn);
                }));
    }
}
