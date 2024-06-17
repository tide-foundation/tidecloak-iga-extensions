package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.multipart.FileUpload;
import org.jboss.resteasy.reactive.server.multipart.FormValue;
import org.jboss.resteasy.reactive.server.multipart.MultipartFormDataInput;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Map;


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
    public Response uploadImage(MultipartFormDataInput input) {
        String fileName = "";
        String fileType = "";
        InputStream fileData = null;

        try {
            // Get the form data map
            Map<String, Collection<FormValue>> formData = input.getValues();

            // Extract file data
            Collection<FormValue> fileParts = formData.get("fileData");
            if (fileParts != null && !fileParts.isEmpty()) {
                FormValue filePart = fileParts.iterator().next();
                fileData = filePart.getFileItem().getInputStream();
            }

            // Extract file name
            Collection<FormValue> fileNameParts = formData.get("fileName");
            if (fileNameParts != null && !fileNameParts.isEmpty()) {
                FormValue fileNamePart = fileNameParts.iterator().next();
                fileName = fileNamePart.getValue();
            }

            // Extract file type
            Collection<FormValue> fileTypeParts = formData.get("fileType");
            if (fileTypeParts != null && !fileTypeParts.isEmpty()) {
                FormValue fileTypePart = fileTypeParts.iterator().next();
                fileType = fileTypePart.getValue();
            }

            // Validate inputs
            if (fileData == null || fileName == null || fileName.isEmpty() || fileType == null || fileType.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid file, file name, or file type").type(MediaType.TEXT_PLAIN).build();
            }

            // Define the directory where files will be saved
            String uploadDir = "uploads";
            File uploadDirFile = new File(uploadDir);
            if (!uploadDirFile.exists()) {
                uploadDirFile.mkdirs();
            }

            // Create the file name with the type prefix
            String newFileName = fileType + "_" + fileName;

            // Check if a file of the same type already exists and delete it
            String finalFileType = fileType;
            File[] existingFiles = uploadDirFile.listFiles((dir, name) -> name.startsWith(finalFileType + "_"));
            if (existingFiles != null) {
                for (File existingFile : existingFiles) {
                    existingFile.delete();
                }
            }

            // Create the new file in the upload directory
            File file = new File(uploadDirFile, newFileName);
            try (FileOutputStream outputStream = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileData.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }

                return Response.ok("File uploaded successfully").type(MediaType.TEXT_PLAIN).build();
            } catch (Exception e) {
                e.printStackTrace();
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File upload failed: " + e.getMessage()).type(MediaType.TEXT_PLAIN).build();
            }

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File upload failed: " + e.getMessage()).type(MediaType.TEXT_PLAIN).build();
        }
    }
    @DELETE
    @Path("images/{type}/delete")
    public Response deleteImage(@PathParam("type") String type) {
        // Define the directory where files are saved
        String uploadDir = "uploads";
        File uploadDirFile = new File(uploadDir);
        if (!uploadDirFile.exists() || !uploadDirFile.isDirectory()) {
            return Response.status(Response.Status.NOT_FOUND).entity("Upload directory does not exist").type(MediaType.TEXT_PLAIN).build();
        }

        // Get all files that match the given file type
        File[] filesToDelete = uploadDirFile.listFiles((dir, name) -> name.startsWith(type + "_"));
        if (filesToDelete == null || filesToDelete.length == 0) {
            return Response.status(Response.Status.NOT_FOUND).entity("No files found for the specified type").type(MediaType.TEXT_PLAIN).build();
        }

        // Attempt to delete each file
        for (File file : filesToDelete) {
            if (!file.delete()) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to delete file: " + file.getName()).type(MediaType.TEXT_PLAIN).build();
            }
        }

        return Response.ok("Files of type " + type + " deleted successfully").type(MediaType.TEXT_PLAIN).build();
    }


    @GET
    @Path("images/{type}/name")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getFileName(@PathParam("type") String type) {
        // Define the directory where files are saved
        String uploadDir = "uploads";
        File uploadDirFile = new File(uploadDir);

        // Find the file with the specified type
        File[] files = uploadDirFile.listFiles((dir, name) -> name.startsWith(type + "_"));
        if (files == null || files.length == 0) {
            return Response.ok().build();
        }
        File file = files[0]; // There should be only one file per type
        String fileName = file.getName().substring(type.length() + 1); // Extract the original file name without the type prefix

        return Response.ok(fileName).build();
    }
}
