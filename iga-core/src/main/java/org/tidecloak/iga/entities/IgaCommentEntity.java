package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "IGA_COMMENT")
@NamedQueries({
    @NamedQuery(
        name = "IgaComment.findByChangeRequest",
        query = "SELECT c FROM IgaCommentEntity c WHERE c.changeRequest.id = :crId ORDER BY c.createdAt ASC"
    ),
    @NamedQuery(
        name = "IgaComment.findById",
        query = "SELECT c FROM IgaCommentEntity c WHERE c.id = :id"
    ),
    @NamedQuery(
        name = "IgaComment.deleteByChangeRequest",
        query = "DELETE FROM IgaCommentEntity c WHERE c.changeRequest.id = :crId"
    )
})
public class IgaCommentEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGE_REQUEST_ID", nullable = false)
    private IgaChangeRequestEntity changeRequest;

    @Column(name = "USER_ID", length = 36, nullable = false)
    private String userId;

    @Column(name = "USERNAME", length = 255)
    private String username;

    @Column(name = "COMMENT_TEXT", length = 2000, nullable = false)
    private String comment;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "UPDATED_AT")
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public IgaChangeRequestEntity getChangeRequest() { return changeRequest; }
    public void setChangeRequest(IgaChangeRequestEntity changeRequest) { this.changeRequest = changeRequest; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
