package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RequestChangesUserRecord {
    @JsonProperty("user")
    protected String user;

    @JsonProperty("proofDetailId")
    protected String proofDetailId;

    public RequestChangesUserRecord(String user, String proofDetailId) {
        this.user = user;
        this.proofDetailId = proofDetailId;
    }

}
