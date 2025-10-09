package org.tidecloak.base.iga.ChangeSetProcessors;

public class ChangeSetProcessorFactoryProvider {

    /**
     * @return RagnarokChangeSetProcessorFactory if present on the classpath,
     *         otherwise a plain ChangeSetProcessorFactory.
     */
    public static ChangeSetProcessorFactory getFactory() {
        try {
            Class<?> override = Class.forName(
                    "org.ragnarok.ChangeSets.RagnarokChangeSetProcessorFactory"
            );
            // safe to cast because it extends ChangeSetProcessorFactory
            return (ChangeSetProcessorFactory)
                    override.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException cnfe) {
            // override jar not present → use the default
            return new ChangeSetProcessorFactory();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to instantiate RagnarokChangeSetProcessorFactory", e
            );
        }
    }
}
