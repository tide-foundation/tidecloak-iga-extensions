//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.tidecloak.shared.models.InitializerCertificateModel;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.UUID;

public class InitializerCertificatePayload {
    @JsonProperty("vendor")
    protected String vendor;
    @JsonProperty("resource")
    protected String resource;
    @JsonProperty("threshold")
    protected int threshold;
    @JsonProperty("id")
    private UUID id;
    @JsonProperty("signmodels")
    protected ArrayList<String> signModels;

    public InitializerCertificatePayload() {
    }

    public InitializerCertificatePayload(String vendor, String resource, ArrayList<String> signModels, int threshold) {
        this.vendor = vendor;
        this.resource = resource;
        this.signModels = signModels;
        this.id = UUID.randomUUID();
        this.threshold = threshold;
    }

    public String getId() {
        return this.id.toString();
    }

    public String vendor() {
        return this.vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public void setThreshold(int t) {
        this.threshold = t;
    }

    public int getThreshold() {
        return this.threshold;
    }

    public String getResource() {
        return this.resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public ArrayList<String> getSignModels() {
        return this.signModels;
    }

    public void setSignModels(ArrayList<String> signModels) {
        this.signModels = signModels;
    }

    public void addSignModel(String signModel) {
        this.signModels.add(signModel);
    }
}
