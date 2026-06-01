package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 7 ({@code user_identity}) — definition bundle, target = user UUID.
 * Mirrors ork {@code UserIdentityAttestationUnit}. {@code email}/{@code first_name}/
 * {@code last_name} are EXPLICIT {@code null} when absent (the legacy exporter
 * passed the raw {@code UserModel} getters straight through). {@code attributes}
 * is the {@code [{name,values[]}]} form (values already LONG_VALUE-resolved by KC).
 */
public final class UserIdentityUnit extends AttestationUnit {

    private final String userId;
    private final String username;
    private final String email;
    private final boolean emailVerified;
    private final String firstName;
    private final String lastName;
    private final List<NameValues> attributes;

    public UserIdentityUnit(String realmId, String userId, String username,
                            String email, boolean emailVerified, String firstName,
                            String lastName, List<NameValues> attributes) {
        super(realmId, userId);
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
        this.attributes = attributes;
    }

    @Override
    public String unitType() {
        return "user_identity";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("user_id", userId);
        p.put("username", username);
        p.put("realm_id", realmId);
        p.put("email", email);              // explicit null if absent
        p.put("email_verified", emailVerified);
        p.put("first_name", firstName);     // explicit null if absent
        p.put("last_name", lastName);       // explicit null if absent
        p.put("attributes", nameValuesMulti(attributes));
        return p;
    }
}
