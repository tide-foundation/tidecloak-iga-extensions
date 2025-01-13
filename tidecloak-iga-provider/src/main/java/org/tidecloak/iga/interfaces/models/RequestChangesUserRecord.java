package org.tidecloak.iga.interfaces.models;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RequestChangesUserRecord {
    @JsonProperty("username")
    protected String username;

    @JsonProperty("clientId")
    protected String clientId;

    @JsonProperty("proofDetailId")
    protected String proofDetailId; // need this for requests

    @JsonProperty("accessDraft")
    protected String accessDraft; // need this for requests

    // show affected user
    // show for affected client

    public RequestChangesUserRecord(String username, String proofDetailId, String clientId, String accessDraft) {
        this.username = username;
        this.proofDetailId = proofDetailId;
        this.clientId = clientId;
        this.accessDraft = accessDraft;
    }

}
