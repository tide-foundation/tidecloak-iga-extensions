package org.tidecloak.iga.ChangeSetProcessors.keys;
import org.tidecloak.shared.enums.ChangeSetType;

import java.util.Objects;

public class ChangeRequestKey {
    private final String userId;
    private final String clientId;
    private final ChangeSetType changeSetType;


    public ChangeRequestKey(String userId, String clientId, ChangeSetType changeSetType) {
        this.userId = userId;
        this.clientId = clientId;
        this.changeSetType = changeSetType;
    }

    // Getters, equals, and hashCode required for map keys
    public String getUserId() { return userId; }
    public String getClientId() { return clientId; }
    public ChangeSetType getChangeSetType() { return changeSetType; }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ChangeRequestKey that)) return false;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(changeSetType, that.changeSetType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, clientId, changeSetType);
    }

    @Override
    public String toString() {
        return "UserClientKey{" + "userId=" + userId + ", clientId=" + clientId + ", changeSetType=" + changeSetType +'}';
    }
}
