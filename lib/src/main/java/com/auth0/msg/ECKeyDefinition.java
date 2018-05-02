package com.auth0.msg;

public class ECKeyDefinition extends KeyDefinition {
    private String crv;

    public ECKeyDefinition(KeyType type, KeyUseCase useCase, String crv) {
        this.type = type;
        this.useCase.add(useCase);
        this.crv = crv;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }
}