package org.tidecloak.jpa.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;

@Embeddable
public class ChangeRequestKey implements Serializable {

    @Column(name = "MAPPING_ID", length = 36)
    private String mappingId;

    @Column(name = "CHANGE_REQUEST_ID", length = 36)
    private String changeRequestId;

    public ChangeRequestKey() {
    }

    public ChangeRequestKey(String mappingId, String changeRequestId) {
        this.mappingId = mappingId;
        this.changeRequestId = changeRequestId;
    }

    // Getters and setters
    public String getMappingId() {
        return mappingId;
    }

    public void setMappingId(String mappingId) {
        this.mappingId = mappingId;
    }

    public String getChangeRequestId() {
        return changeRequestId;
    }

    public void setChangeRequestId(String changeRequestId) {
        this.changeRequestId = changeRequestId;
    }

    // equals and hashCode are required for composite keys
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ChangeRequestKey)) return false;
        ChangeRequestKey that = (ChangeRequestKey) o;
        return Objects.equals(mappingId, that.mappingId) &&
                Objects.equals(changeRequestId, that.changeRequestId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mappingId, changeRequestId);
    }
}
