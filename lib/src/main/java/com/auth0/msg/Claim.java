package com.auth0.msg;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Claim {
    public String name;
    @JsonProperty("map")
    @JsonDeserialize(keyUsing = ClaimDeserializer.class)
    public Map<MessageType, List<Object>> allowedValues;
    public ClaimType type;

    public Claim(String name) {
        this(name, Collections.<MessageType, List<Object>>emptyMap(), null);
    }

    public Claim(String name, ClaimType type) {
        this(name, Collections.<MessageType, List<Object>>emptyMap(), type);
    }

    @JsonCreator
    public Claim(String name, Map<MessageType, List<Object>> allowedValues, ClaimType type) {
        this.name = name;
        this.allowedValues = allowedValues;
        this.type = type;
    }

    public ClaimType getType() {
        return type;
    }

    public void setType(ClaimType type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    //hashCode()

}
