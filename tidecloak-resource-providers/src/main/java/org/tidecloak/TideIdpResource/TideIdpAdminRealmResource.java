package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class TideIdpAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideIdpAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("images/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response uploadImage(@BeanParam FileUploadForm form) {
        if (form.getFileData() == null || form.getFileName() == null || form.getFileName().isEmpty() || form.getFileType() == null || form.getFileType().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid file, file name, or file type").build();
        }

        // Define the directory where files will be saved
        String uploadDir = "uploads";
        File uploadDirFile = new File(uploadDir);
        if (!uploadDirFile.exists()) {
            uploadDirFile.mkdirs();
        }

        // Create the file name with the type prefix
        String fileName = form.getFileType() + "_" + form.getFileName();

        // Check if a file of the same type already exists and delete it
        File[] existingFiles = uploadDirFile.listFiles((dir, name) -> name.startsWith(form.getFileType() + "_"));
        if (existingFiles != null) {
            for (File existingFile : existingFiles) {
                existingFile.delete();
            }
        }

        // Create the new file in the upload directory
        File file = new File(uploadDirFile, fileName);
        try (InputStream inputStream = form.getFileData();
             FileOutputStream outputStream = new FileOutputStream(file)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            return Response.ok().build();
        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File upload failed: " + e.getMessage()).build();
        }
    }

}
