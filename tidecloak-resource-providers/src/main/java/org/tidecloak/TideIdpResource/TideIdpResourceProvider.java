package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
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
import java.io.FileOutputStream;
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
    @Path("image/{type}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getFile(@PathParam("type") String type) {
        // Define the directory where files are saved
        String uploadDir = "uploads";
        File uploadDirFile = new File(uploadDir);

        // Find the file with the specified type
        File[] files = uploadDirFile.listFiles((dir, name) -> name.startsWith(type + "_"));
        if (files == null || files.length == 0) {
            return Response.status(Response.Status.NOT_FOUND).entity("File not found").build(); // server a default image here then
        }

        File file = files[0]; // There should be only one file per type

        try (InputStream inputStream = new FileInputStream(file)) {
            byte[] fileData = new byte[(int) file.length()];
            inputStream.read(fileData);

            return Response.ok(fileData, MediaType.APPLICATION_OCTET_STREAM)
                    .header("Content-Disposition", "attachment; filename=\"" + file.getName().substring(type.length() + 1) + "\"")
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File retrieval failed: " + e.getMessage()).build(); // server default image then
        }
    }
}


