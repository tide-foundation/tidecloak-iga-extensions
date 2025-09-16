package org.tidecloak.base.iga.ChangeSetProcessors;

import org.tidecloak.shared.enums.ChangeSetType;

public class ChangeSetProcessorFactory {

    private static final ChangeSetProcessor NOOP = new ChangeSetProcessor(){};

    public ChangeSetProcessor getProcessor(ChangeSetType type) {
        // Always return a no-op processor; the old workflow engine was removed.
        return NOOP;
    }
}
