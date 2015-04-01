package com.auth0.jwt;


import java.util.ArrayList;
import java.util.List;

public class JWTAudienceException extends JWTVerifyException {
    private Object audienceNode;

    public JWTAudienceException(Object audienceNode) {
        this.audienceNode = audienceNode;
    }

    public JWTAudienceException(String message, Object audienceNode) {
        super(message);
        this.audienceNode = audienceNode;
    }

    public List<String> getAudience() {
        ArrayList<String> audience = new ArrayList<String>();
        if (audienceNode instanceof List) {
            for (Object jsonNode : (List)audienceNode) {
                audience.add(jsonNode.toString());
            }
        } else if (audienceNode instanceof String) {
            audience.add((String)audienceNode);
        }
        return audience;
    }
}
