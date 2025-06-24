package org.tidecloak.base.iga.ChangeSetProcessors.keys;
import java.util.Objects;

public class UserClientKey {
    private final String userId;
    private final String clientId;

    public UserClientKey(String userId, String clientId) {
        this.userId = userId;
        this.clientId = clientId;
    }

    // Getters, equals, and hashCode required for map keys
    public String getUserId() { return userId; }
    public String getClientId() { return clientId; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserClientKey that)) return false;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(clientId, that.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, clientId);
    }

    @Override
    public String toString() {
        return "UserClientKey{" + "userId=" + userId + ", clientId=" + clientId + '}';
    }
}
