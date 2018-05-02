package com.auth0.msg;

import java.util.List;

public class RSAKeyDefinition extends KeyDefinition {
    private String size;
    private String filename;
    private String filepath;

    public RSAKeyDefinition(KeyType type, KeyUseCase useCase, String size, String filename, String filepath) {
        this.type = type;
        this.useCase.add(useCase);
        this.size = size;
        this.filename = filename;
        this.filepath = filepath;
    }

    public RSAKeyDefinition(KeyType type, List<KeyUseCase> useCase) {
        super(type, useCase);
    }

    public String getSize() {
        return size;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
    }
}
