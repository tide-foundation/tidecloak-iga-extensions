package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import org.tidecloak.shared.enums.ChangeSetType;

@NamedQueries({
        @NamedQuery(
                name = "getCommentsByChangesetRequestId",
                query = "SELECT c FROM ChangesetCommentEntity c WHERE c.changesetRequestId = :changesetRequestId ORDER BY c.timestamp ASC"
        ),
})

@Entity
@Table(name = "CHANGESET_COMMENTS")
public class ChangesetCommentEntity {

    @Id
    @Column(name = "ID")
    private String id;

    @Column(name = "CHANGESET_REQUEST_ID")
    private String changesetRequestId;

    @Enumerated(EnumType.STRING)
    @Column(name = "CHANGE_SET_TYPE")
    private ChangeSetType changesetType;

    @Column(name = "USER_ID")
    private String userId;

    @Column(name = "USERNAME")
    private String username;

    @Column(name = "COMMENT", length = 2000)
    private String comment;

    @Column(name = "TIMESTAMP")
    private Long timestamp = System.currentTimeMillis() / 1000;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getChangesetRequestId() { return changesetRequestId; }
    public void setChangesetRequestId(String changesetRequestId) { this.changesetRequestId = changesetRequestId; }

    public ChangeSetType getChangesetType() { return changesetType; }
    public void setChangesetType(ChangeSetType changesetType) { this.changesetType = changesetType; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }
}
