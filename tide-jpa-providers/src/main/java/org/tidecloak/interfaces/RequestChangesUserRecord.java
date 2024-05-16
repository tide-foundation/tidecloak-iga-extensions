package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RequestChangesUserRecord {
    @JsonProperty("username")
    protected String username;

    @JsonProperty("clientName")
    protected String clientName;

    @JsonProperty("proofDetailId")
    protected String proofDetailId; // need this for requests

    // show affected user
    // show for affected client

    public RequestChangesUserRecord(String username, String proofDetailId, String clientName) {
        this.username = username;
        this.proofDetailId = proofDetailId;
        this.clientName = clientName;
    }

}
