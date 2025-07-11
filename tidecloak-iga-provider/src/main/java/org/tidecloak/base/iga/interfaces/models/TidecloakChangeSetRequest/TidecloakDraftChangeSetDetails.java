package org.tidecloak.base.iga.interfaces.models.TidecloakChangeSetRequest;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TidecloakDraftChangeSetDetails {

    @JsonProperty("user")
    protected  String username;

    @JsonProperty("UserClientAccessDraft")
    protected  String UserClientAccessDraft;

    @JsonProperty("keywords")
    protected String keywords;

    public TidecloakDraftChangeSetDetails(String username, String UserClientAccessDraft, String keywords){
        this.username = username;
        this.UserClientAccessDraft = UserClientAccessDraft;
        this.keywords = keywords;
    }

}