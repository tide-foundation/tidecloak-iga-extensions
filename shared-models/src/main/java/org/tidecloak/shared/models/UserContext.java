//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.tidecloak.shared.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Base64;

public class UserContext {
    private final JsonNode contents;

    public UserContext(String data) {
        ObjectMapper mapper = new ObjectMapper();

        try {
            this.contents = mapper.readTree(data);
        } catch (JsonProcessingException var4) {
            throw new RuntimeException("Could not serialize data into json format");
        }
    }

    public UserContext(JsonNode data) {
        this.contents = data;
    }

    public void setThreshold(int threshold) {
        ObjectNode objectNode = (ObjectNode)this.contents;
        if (threshold <= 0) {
            objectNode.remove("Threshold");
        } else {
            objectNode.put("Threshold", threshold);
        }

    }

    public int getThreshold() {
        ObjectNode objectNode = (ObjectNode)this.contents;
        JsonNode t = objectNode.get("Threshold");
        return t != null ? t.asInt() : 0;
    }

    public void setInitCertHash(byte[] hash) {
        ObjectNode objectNode = (ObjectNode)this.contents;
        if (hash == null) {
            objectNode.remove("InitCertHash");
        } else {
            objectNode.put("InitCertHash", Base64.getUrlEncoder().encodeToString(hash));
        }

    }

    public byte[] getInitCertHash() {
        ObjectNode objectNode = (ObjectNode)this.contents;
        JsonNode initCertHash = objectNode.get("InitCertHash");
        return initCertHash != null ? Base64.getUrlDecoder().decode(initCertHash.asText()) : null;
    }

    public String ToString() {
        ObjectMapper mapper = new ObjectMapper();

        try {
            return mapper.writeValueAsString(this.contents);
        } catch (JsonProcessingException var3) {
            throw new RuntimeException("Could not write json contents into a byte array");
        }
    }

    public byte[] Encode() {
        ObjectMapper mapper = new ObjectMapper();

        try {
            return mapper.writeValueAsBytes(this.contents);
        } catch (JsonProcessingException var3) {
            throw new RuntimeException("Could not write json contents into a byte array");
        }
    }
}
