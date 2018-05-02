package com.auth0.msg;

import java.util.List;
import java.util.Map;

public class ProviderConfigurationResponse extends AbstractMessage{

    public ProviderConfigurationResponse() {
    }


    public ProviderConfigurationResponse(Map<Claim, Object> claims){
        super(claims);
    }

    @Override
    protected List<Claim> getRequiredClaims() {
        return null;
    }

    @Override
    public Map<Claim, Object> getClaims() throws InvalidClaimsException {
        return super.getClaims();
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
