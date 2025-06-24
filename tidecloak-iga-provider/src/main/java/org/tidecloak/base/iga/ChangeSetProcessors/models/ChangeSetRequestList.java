package org.tidecloak.base.iga.ChangeSetProcessors.models;

import java.util.List;

public class ChangeSetRequestList {
    private List<ChangeSetRequest> changeSets;

    public List<ChangeSetRequest> getChangeSets() {
        return changeSets;
    }

    public void setChangeSets(List<ChangeSetRequest> changeSets) {
        this.changeSets = changeSets;
    }
}
