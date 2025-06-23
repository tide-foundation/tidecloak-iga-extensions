//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.tidecloak.shared.models.InitializerCertificateModel;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

public class InitializerCertificate {
    @JsonProperty("header")
    protected InitializerCertificateHeader initCertHeader;
    @JsonProperty("payload")
    protected InitializerCertificatePayload initCertPayload;

    public InitializerCertificate() {
    }

    public InitializerCertificate(InitializerCertificateHeader initCertHeader, InitializerCertificatePayload initCertPayload) {
        this.initCertHeader = initCertHeader;
        this.initCertPayload = initCertPayload;
    }

    public static InitializerCertificate FromString(String json) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return (InitializerCertificate)mapper.readValue(json, InitializerCertificate.class);
    }

    public byte[] hash() {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException var3) {
            System.out.println("SHA-512 not found");
            return null;
        }

        return md.digest(this.Encode());
    }

    public InitializerCertificateHeader getHeader() {
        return this.initCertHeader;
    }

    public void setHeader(InitializerCertificateHeader initCertHeader) {
        this.initCertHeader = initCertHeader;
    }

    public InitializerCertificatePayload getPayload() {
        return this.initCertPayload;
    }

    public void setPayload(InitializerCertificatePayload payload) {
        this.initCertPayload = payload;
    }

    public byte[] Encode() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String header = Base64.getUrlEncoder().encodeToString(mapper.writeValueAsString(this.getHeader()).getBytes(StandardCharsets.UTF_8));
            String payload = Base64.getUrlEncoder().encodeToString(mapper.writeValueAsString(this.getPayload()).getBytes(StandardCharsets.UTF_8));
            return (header + "." + payload).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException var4) {
            throw new RuntimeException("Could not serialize InitializerCertificate");
        }
    }

    public static InitializerCertificate constructInitCert(String vvkId, String alg, String vn, String vendor, String resource, int threshold, ArrayList<String> signModels) {
        InitializerCertificateHeader header = new InitializerCertificateHeader(vvkId, alg, vn);
        InitializerCertificatePayload payload = new InitializerCertificatePayload(vendor, resource, signModels, threshold);
        return new InitializerCertificate(header, payload);
    }
}
