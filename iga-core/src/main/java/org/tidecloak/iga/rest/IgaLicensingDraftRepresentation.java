package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA licensing draft — the sidecar to an
 * INSTALL_LICENSE or ROTATE_LICENSE change request.
 */
public class IgaLicensingDraftRepresentation {

    private String id;
    private String changeRequestId;
    private String realmId;
    private String actionType;
    private String signature;
    private Long createdAt;
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getChangeRequestId() { return changeRequestId; }
    public void setChangeRequestId(String changeRequestId) { this.changeRequestId = changeRequestId; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
