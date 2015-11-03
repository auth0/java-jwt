package com.auth0.jwt;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

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
        ArrayList<String> audience = new ArrayList<>();
        if (audienceNode instanceof Collection) {
            for (Object jsonNode : (Collection) audienceNode) {
                audience.add(jsonNode.toString());
            }
	    } else if (audienceNode instanceof String) {
            audience.add(audienceNode.toString());
        }
        return audience;
    }
}
