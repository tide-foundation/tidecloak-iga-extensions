package org.tidecloak.TideIdpResource;

import jakarta.ws.rs.FormParam;

import java.io.InputStream;

public class FileUploadForm {

    @FormParam("fileData")
    private InputStream fileData;

    @FormParam("fileName")
    private String fileName;

    @FormParam("fileType")
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