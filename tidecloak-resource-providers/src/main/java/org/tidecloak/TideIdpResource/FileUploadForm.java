package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.FormParam;
import org.jboss.resteasy.reactive.PartType;

import java.io.InputStream;

public class FileUploadForm {
    @FormParam("fileData")
    @PartType("application/octet-stream")
    private InputStream fileData;

    @FormParam("fileName")
    @PartType("text/plain")
    private String fileName;

    @FormParam("fileType")
    @PartType("text/plain")
    private String fileType;

    // Getters and setters
    public InputStream getFileData() {
        return fileData;
    }

    public void setFileData(InputStream fileData) {
        this.fileData = fileData;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
}
