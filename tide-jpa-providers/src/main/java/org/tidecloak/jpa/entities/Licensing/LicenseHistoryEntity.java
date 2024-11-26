package org.tidecloak.jpa.entities.Licensing;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ComponentEntity;

@Entity
@Table(name="LICENSE_HISTORY")
public class LicenseHistoryEntity {
    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne
    @JoinColumn(name = "PROVIDER_ID", referencedColumnName = "ID")
    protected ComponentEntity componentEntity;

    @Column(name = "VRK")
    protected String VRK;

    @Column(name = "GVRK")
    protected String GVRK;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public ComponentEntity getComponentEntity() {
        return componentEntity;
    }

    public  void setComponentEntity(ComponentEntity componentEntity) {
        this.componentEntity = componentEntity;
    }

    public String getVRK() {
        return VRK;
    }

    public void setVRK(String VRK) {

        this.VRK = VRK;
    }

    public String getGVRK() {
        return  GVRK;
    }

    public void setGVRK(String GVRK) {
        this.GVRK = GVRK;
    }

}
