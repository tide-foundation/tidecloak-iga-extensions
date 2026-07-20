package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA comment, returned by the REST API.
 *
 * <p>For backwards compatibility the response carries the comment text under
 * BOTH {@code comment} and {@code body}, and the author username under BOTH
 * {@code username} and {@code authorUsername}. The admin-ui SDK type
 * (libs/keycloak-admin-client/.../igaCommentRepresentation.ts) reads
 * {@code body} / {@code authorUsername} / {@code changeRequestId}; older
 * callers that read {@code comment} / {@code username} continue to work.
 */
public class IgaCommentRepresentation {

    private String id;
    private String changeRequestId;
    private String userId;
    private String username;
    private String comment;
    private Long createdAt;
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getChangeRequestId() { return changeRequestId; }
    public void setChangeRequestId(String changeRequestId) { this.changeRequestId = changeRequestId; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    /** Alias for {@link #getUsername()} — emitted as {@code authorUsername} for the admin-ui SDK. */
    public String getAuthorUsername() { return username; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    /** Alias for {@link #getComment()} — emitted as {@code body} for the admin-ui SDK. */
    public String getBody() { return comment; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
