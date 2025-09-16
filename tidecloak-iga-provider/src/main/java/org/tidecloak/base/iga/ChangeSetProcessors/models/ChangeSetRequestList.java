//  (compat shim)
package org.tidecloak.base.iga.ChangeSetProcessors.models;

import java.util.List;

public class ChangeSetRequestList {
    private List<ChangeSetRequest> changeSets;
    public ChangeSetRequestList(){}
    public ChangeSetRequestList(List<ChangeSetRequest> changeSets){ this.changeSets = changeSets; }
    public List<ChangeSetRequest> getChangeSets() { return changeSets; }
    public void setChangeSets(List<ChangeSetRequest> changeSets) { this.changeSets = changeSets; }
}
