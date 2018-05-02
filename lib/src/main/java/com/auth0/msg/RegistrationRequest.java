package com.auth0.msg;

import java.util.List;
import java.util.Map;

public class RegistrationRequest extends AbstractMessage{

    public RegistrationRequest(Map<Claim, Object> claims){
        super(claims);
    }

    @Override
    protected List<Claim> getRequiredClaims() {
        return null;
    }

    @Override
    public Map<Claim, Object> getClaims() throws InvalidClaimsException {
        return null;
    }

    @Override
    public String getRequestWithEndpoint(String authorizationEndpoint, DataLocation location) {
        return null;
    }

    @Override
    public boolean hasError() {
        return false;
    }
}
