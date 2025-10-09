package org.tidecloak.base.iga.ChangeSetProcessors;

import org.tidecloak.base.iga.ChangeSetProcessors.processors.RealmLicenseProcessor;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.base.iga.interfaces.models.ChangeSetTypeEntity;

import java.util.function.Supplier;

public class ChangeSetProcessorFactory {

    @SuppressWarnings("unchecked")
    public <T> ChangeSetProcessor<T> getProcessor(ChangeSetType type) {
        if(type == ChangeSetType.REALM_LICENSING) {
            Supplier<? extends org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor<?>> supplier = RealmLicenseProcessor::new;
            if (supplier == null) {
                throw new IllegalArgumentException("No processor supplier defined for type: " + type);
            }
            return (ChangeSetProcessor<T>) supplier.get();
        }
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
