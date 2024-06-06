package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class TideIdpResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public TideIdpResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @GET
    @Path("images/{type}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getFile(@PathParam("type") String type) {
        // Define the directory where files are saved
        String uploadDir = "uploads";
        File uploadDirFile = new File(uploadDir);

        // Find the file with the specified type
        File[] files = uploadDirFile.listFiles((dir, name) -> name.startsWith(type + "_"));
        if (files == null || files.length == 0) {
            return Response.status(Response.Status.NOT_FOUND).entity("File not found").type(MediaType.TEXT_PLAIN).build();
        }

        File file = files[0]; // There should be only one file per type

        String fileName = file.getName();
        String fileExtension = getFileExtension(fileName);
        String mimeType = getMimeType(fileExtension);

        try (InputStream inputStream = new FileInputStream(file)) {
            byte[] fileData = new byte[(int) file.length()];
            inputStream.read(fileData);

            return Response.ok(fileData, mimeType)
                    .header("Content-Disposition", "inline; filename=\"" + fileName.substring(type.length() + 1) + "\"")
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File retrieval failed: " + e.getMessage()).type(MediaType.TEXT_PLAIN).build();
        }
    }

    private String getFileExtension(String fileName) {
        int lastIndexOfDot = fileName.lastIndexOf('.');
        if (lastIndexOfDot == -1) {
            return ""; // No extension
        }
        return fileName.substring(lastIndexOfDot + 1);
    }

    private String getMimeType(String fileExtension) {
        switch (fileExtension.toLowerCase()) {
            case "jpg":
            case "jpeg":
                return "image/jpeg";
            case "png":
                return "image/png";
            case "gif":
                return "image/gif";
            case "svg":
                return "image/svg+xml";
            default:
                return MediaType.APPLICATION_OCTET_STREAM;
        }
    }
}


