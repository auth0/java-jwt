package com.auth0.msg;

import java.util.List;

public class KeyDefinition {
    protected KeyType type;
    protected List<KeyUseCase> useCase;

    public KeyDefinition(KeyType type, List<KeyUseCase> useCase) {
        this.type = type;
        this.useCase = useCase;
    }

    public KeyDefinition() {
    }

    public KeyType getType() {
        return type;
    }

    public void setType(KeyType type) {
        this.type = type;
    }

    public List<KeyUseCase> getUseCase() {
        return useCase;
    }

    public void setUseCase(List<KeyUseCase> useCase) {
        this.useCase = useCase;
    }
}