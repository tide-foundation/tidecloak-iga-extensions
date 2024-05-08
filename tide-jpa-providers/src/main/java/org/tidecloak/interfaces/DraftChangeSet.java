package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DraftChangeSet {

    @JsonProperty("changeSetId")
    protected String changeSetId;
    @JsonProperty("changeSetType")
    protected String changeSetType;

    public String getType() {
        return changeSetType;
    }
    public String getChangeSetId() {
        return changeSetId;
    }



}
