package org.tidecloak.base.iga.interfaces.models.TidecloakChangeSetRequest;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class TidecloakUserContextRequest {

    @JsonProperty("TidecloakDraftRecord")
    protected  String tidecloakDraftRecord;

    @JsonProperty("Timestamp")
    protected long timestamp;

    @JsonProperty("DraftChangeSetDetails")
    protected List<String> draftChangeSetDetails;

    public TidecloakUserContextRequest(String TidecloakDraftRecord, long timestamp, List<String> draftChangeSetDetails){
        this.tidecloakDraftRecord = TidecloakDraftRecord;
        this.timestamp = timestamp;
        this.draftChangeSetDetails = draftChangeSetDetails;
    }

    public String getTidecloakDraftRecord() {
        return tidecloakDraftRecord;
    }
    public long getTimestamp() {
        return timestamp;
    }
    public List<String> getDraftChangeSetDetails() {
        return draftChangeSetDetails;
    }
    public void setTidecloakDraftRecord(String tidecloakDraftRecord) {
        this.tidecloakDraftRecord = tidecloakDraftRecord;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
    public void setDraftChangeSetDetails(List<String> draftChangeSetDetails) {
        this.draftChangeSetDetails = draftChangeSetDetails;
    }

}
