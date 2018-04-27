package com.auth0.msg;

import java.util.List;
import java.util.Map;

public class ProviderConfigurationResponse extends AbstractMessage{

    public ProviderConfigurationResponse(Map<ClaimType, Object> claims){
        super(claims);
    }

    @Override
    protected List<ClaimType> getRequiredClaims() {
        return null;
    }

    @Override
    public Map<ClaimType, Object> getClaims() throws InvalidClaimsException {
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
