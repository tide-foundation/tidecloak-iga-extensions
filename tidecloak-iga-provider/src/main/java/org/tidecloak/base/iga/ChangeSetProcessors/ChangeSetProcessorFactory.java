package org.tidecloak.base.iga.ChangeSetProcessors;

import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.base.iga.interfaces.models.ChangeSetTypeEntity;

import java.util.function.Supplier;

public class ChangeSetProcessorFactory {

    @SuppressWarnings("unchecked")
    public <T> ChangeSetProcessor<T> getProcessor(ChangeSetType type) {
        // Fetch the corresponding ChangeSetTypeEntity
        ChangeSetTypeEntity typeEntity = ChangeSetTypeEntity.fromBaseType(type);

        // Use the processor supplier from the entity
        Supplier<? extends ChangeSetProcessor<?>> supplier = typeEntity.getProcessorSupplier();
        if (supplier == null) {
            throw new IllegalArgumentException("No processor supplier defined for type: " + type);
        }

        return (ChangeSetProcessor<T>) supplier.get();
    }
}
