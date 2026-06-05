package org.tidecloak.iga.producer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.UserModel;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.producer.units.UserIdentityUnit;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Regression for the toggle-on backfill abort:
 * {@code AttestationUnit:1 ... 'attributes'.values must contain only strings}.
 *
 * <p>Keycloak's {@code UserAdapter.getAttributes()} merges the standard profile
 * fields (firstName/lastName/email/username) into the multi-valued attribute map
 * via {@code MultivaluedHashMap.add}, which stores a {@code null} value as a
 * single-element list {@code [null]} when the field is absent. The producer used
 * to copy that list verbatim into the {@code user_identity} unit's
 * {@code attributes[].values}, so an attribute carried a CBOR {@code null}
 * element. The ork validator ({@code AttestationUnit.cs GetNameValuesList})
 * rejects any non-string {@code values[]} element, failing the whole bundle.
 *
 * <p>The producer now drops {@code null} elements so every {@code values[]} entry
 * is a string. This test reproduces KC's exact {@code getAttributes()} shape for a
 * user with no firstName/lastName, serializes the unit to CBOR, and asserts that
 * every {@code values[]} element in the envelope is a {@link String} (the precise
 * ork invariant), and that the genuine string attribute survives.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserIdentityAttributesStringCoercionTest {

    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
    private static final String REALM_ID = "realm-uuid-coerce";
    private static final String USER_ID = "user-uuid-coerce";

    @Test
    void nullStandardFieldMergedByKeycloakDoesNotEmitNonStringValue() throws Exception {
        // Reproduce org.keycloak.models.jpa.UserAdapter.getAttributes() for a user
        // with a real custom attribute but absent firstName/lastName:
        //   result.add(FIRST_NAME, null) -> firstName -> [null]
        MultivaluedHashMap<String, String> attrs = new MultivaluedHashMap<>();
        attrs.add("tideUserKey", "200000beadcafe");   // genuine string attribute
        attrs.add(UserModel.FIRST_NAME, null);          // absent -> [null]
        attrs.add(UserModel.LAST_NAME, null);           // absent -> [null]
        attrs.add(UserModel.EMAIL, "ceremony-target@tide.org");
        attrs.add(UserModel.USERNAME, "ceremony-target");

        // Sanity: KC really did store a [null] list (the failure precondition).
        assertEquals(java.util.Collections.singletonList(null), attrs.get(UserModel.FIRST_NAME));

        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("ceremony-target");
        when(user.getEmail()).thenReturn("ceremony-target@tide.org");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getFirstName()).thenReturn(null);
        when(user.getLastName()).thenReturn(null);
        when(user.getAttributes()).thenReturn(attrs);

        UserIdentityUnit unit = RealmAttestationExporter.userIdentity(user, REALM_ID);
        byte[] cbor = unit.serialize();

        // Decode the CBOR envelope and walk attributes[].values exactly as the ork's
        // GetNameValuesList does: assert every element is a String (the ork invariant).
        @SuppressWarnings("unchecked")
        Map<String, Object> env = CBOR.readValue(cbor, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) env.get("payload");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> attributes = (List<Map<String, Object>>) payload.get("attributes");
        assertNotNull(attributes);

        boolean sawTideUserKey = false;
        for (Map<String, Object> entry : attributes) {
            Object name = entry.get("name");
            assertTrue(name instanceof String, "attribute name must be a string");
            Object valuesObj = entry.get("values");
            assertTrue(valuesObj instanceof List, "values must be an array");
            @SuppressWarnings("unchecked")
            List<Object> values = (List<Object>) valuesObj;
            for (Object v : values) {
                // THE INVARIANT the ork enforces (AttestationUnit.cs GetNameValuesList:417):
                assertTrue(v instanceof String,
                        "attributes['" + name + "'].values must contain only strings, got "
                                + (v == null ? "null" : v.getClass().getSimpleName()));
            }
            if ("tideUserKey".equals(name)) {
                sawTideUserKey = true;
                assertEquals(List.of("200000beadcafe"), values);
            }
            // The null-only standard field collapses to an empty values list.
            if (UserModel.FIRST_NAME.equals(name) || UserModel.LAST_NAME.equals(name)) {
                assertTrue(values.isEmpty(),
                        "absent standard field '" + name + "' must collapse to empty values[]");
            }
        }
        assertTrue(sawTideUserKey, "the genuine string attribute must survive coercion");
    }
}
