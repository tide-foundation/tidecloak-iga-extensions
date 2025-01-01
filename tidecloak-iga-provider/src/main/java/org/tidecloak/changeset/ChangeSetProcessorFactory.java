package org.tidecloak.changeset;

import org.tidecloak.changeset.processors.UserRoleProcessor;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class ChangeSetProcessorFactory {
    private final Map<Class<?>, Supplier<? extends ChangeSetProcessor<?>>> processorRegistry = new HashMap<>();

    public ChangeSetProcessorFactory() {
        // Register processors using the entity class from ChangeSetType
        for (ChangeSetType type : ChangeSetType.values()) {
            registerProcessor(type.getEntityClass(), resolveProcessorForType(type));
        }
    }

    private Supplier<? extends ChangeSetProcessor<?>> resolveProcessorForType(ChangeSetType type) {
        return switch (type) {
            case ROLE -> RoleProcessor::new; // Supplier for RoleProcessor
            case USER -> UserProcessor::new; // Supplier for UserProcessor
            case USER_ROLE -> UserRoleProcessor::new; // Supplier for UserRoleProcessor
            // Add other cases as needed
            default -> throw new IllegalArgumentException("No processor defined for type: " + type);
        };
    }

    private void registerProcessor(Class<?> entityClass, Supplier<? extends ChangeSetProcessor<?>> processor) {
        processorRegistry.put(entityClass, processor);
    }

    // generics in Java are erased at runtime, so supress warnings.
    @SuppressWarnings("unchecked")
    public <T> ChangeSetProcessor<T> getProcessor(ChangeSetType type) {
        // Get the supplier with the correct wildcard type
        Supplier<? extends ChangeSetProcessor<?>> supplier = processorRegistry.get(type.getEntityClass());
        if (supplier == null) {
            throw new IllegalArgumentException("No processor registered for type: " + type.getEntityClass().getName());
        }

        // Use a wrapper to bridge the variance gap
        return (ChangeSetProcessor<T>) supplier.get();
    }
}
