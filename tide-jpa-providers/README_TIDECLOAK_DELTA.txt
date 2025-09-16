# TIDECLOAK IMPLEMENTATION — Liquibase-only delta for `tide-jpa-providers`

This package adds the **preview/replay** entities and a **Liquibase** changelog (no Flyway).

## Files
- `src/main/java/org/tidecloak/preview/db/ActiveContextRevisionEntity.java`
- `src/main/java/org/tidecloak/preview/db/TokenPreviewEntity.java`
- `src/main/java/org/tidecloak/preview/db/TokenPreviewBundleEntity.java`
- `src/main/java/org/tidecloak/jpa/TidePreviewJpaEntityProvider.java`
- `src/main/java/org/tidecloak/jpa/TidePreviewJpaEntityProviderFactory.java`
- `src/main/resources/META-INF/tidecloak-preview-changelog.xml`
- `src/main/resources/META-INF/services/org.keycloak.connections.jpa.JpaEntityProviderFactory`

## How it wires into Keycloak
- We register a **JpaEntityProvider** so Keycloak picks up the new entities and runs Liquibase at boot.
- The changelog file is `META-INF/tidecloak-preview-changelog.xml` (kept separate from your existing changelog).
- No destructive changes. New tables only.

## Install
1. Drop these files into your `tide-jpa-providers` module.
2. Ensure the module is on the classpath as usual.
3. Build. On first boot, Liquibase will create:
   - `tide_active_context_revision`
   - `tide_token_preview`
   - `tide_token_preview_bundle`

## Notes
- If your project already has a custom `JpaEntityProvider`, it’s fine to have multiple; Keycloak will run all declared changelogs.
- To remove legacy preview tables later, uncomment the "drop" changeset (after confirming nothing uses them).

Generated: 2025-09-16T04:45:10.336304
