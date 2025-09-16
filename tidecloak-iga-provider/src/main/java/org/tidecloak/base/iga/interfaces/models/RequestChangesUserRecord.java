package org.tidecloak.base.iga.interfaces.models;

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

    public String getUsername(){
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getProofDetailId() {
        return this.proofDetailId;
    }

    public void setProofDetailId(String proofDetailId) {
        this.proofDetailId = proofDetailId;
    }

    public String getAccessDraft() {
        return this.accessDraft;
    }

    public void setAccessDraft(String accessDraft) {
        this.accessDraft = accessDraft;
    }

}