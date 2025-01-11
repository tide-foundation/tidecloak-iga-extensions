package org.tidecloak.changeset;

import org.tidecloak.changeset.processors.*;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.interfaces.ChangeSetTypeEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class ChangeSetProcessorFactory {
    private final Map<Class<?>, Supplier<? extends ChangeSetProcessor<?>>> processorRegistry = new HashMap<>();

    public ChangeSetProcessorFactory() {
        // Register processors using the entity class from ChangeSetTypeEntity
        for (ChangeSetTypeEntity typeEntity : ChangeSetTypeEntity.values()) {
            registerProcessor(typeEntity.getEntityClass(), resolveProcessorForType(typeEntity.getBaseType()));
        }
    }

    private Supplier<? extends ChangeSetProcessor<?>> resolveProcessorForType(ChangeSetType type) {
        return switch (type) {
//            case ROLE -> RoleProcessor::new; // Supplier for RoleProcessor
//            case USER -> UserProcessor::new; // Supplier for UserProcessor
            case COMPOSITE_ROLE -> CompositeRoleProcessor::new;
            case USER_ROLE -> UserRoleProcessor::new;
            case CLIENT_FULLSCOPE -> ClientFullScopeProcessor::new;
            default -> throw new IllegalArgumentException("No processor defined for type: " + type);
        };
    }

    private void registerProcessor(Class<?> entityClass, Supplier<? extends ChangeSetProcessor<?>> processor) {
        processorRegistry.put(entityClass, processor);
    }

    @SuppressWarnings("unchecked")
    public <T> ChangeSetProcessor<T> getProcessor(ChangeSetType type) {
        // Retrieve the corresponding entity class from ChangeSetTypeEntity
        ChangeSetTypeEntity typeEntity = ChangeSetTypeEntity.valueOf(type.name());
        if (typeEntity == null) {
            throw new IllegalArgumentException("No entity defined for type: " + type);
        }

        // Use the entity class to fetch the supplier from the registry
        Supplier<? extends ChangeSetProcessor<?>> supplier = processorRegistry.get(typeEntity.getEntityClass());
        if (supplier == null) {
            throw new IllegalArgumentException("No processor registered for type: " + typeEntity.getEntityClass().getName());
        }

        return (ChangeSetProcessor<T>) supplier.get();
    }
}
