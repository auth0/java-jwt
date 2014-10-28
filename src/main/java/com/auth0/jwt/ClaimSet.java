package com.auth0.jwt;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

public class ClaimSet {

	private long exp;
    protected String iss;
    protected long iat;
    protected String qsh;
    protected String sub;
    protected List<String> aud;
	
	public long getExp() {
		return exp;
	}

	public void setExp(long exp) {
		this.exp = (long)(System.currentTimeMillis() / 1000L) + exp;
	}

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public long getIat() {
        return iat;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    public String getQsh() {
        return qsh;
    }

    public void setQsh(String qsh) {
        this.qsh = qsh;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public List<String> getAud() {
        return aud;
    }

    public void setAud(List<String> aud) {
        this.aud = aud;
    }

    public ObjectNode build(){
        ObjectNode localClaimSet = JsonNodeFactory.instance.objectNode();
        ArrayNode localAudArray = JsonNodeFactory.instance.arrayNode();
        if(this.getExp() > 0) {
            localClaimSet.put("exp", this.getExp());
        }
        if (this.getAud()!=null && this.getAud().size() >0){
            for (String str : this.getAud()){
                localAudArray.add(str);
            }
            localClaimSet.put("aud", localAudArray);
        }
        if (this.getIss() != null && this.getIss().length() >0) {
            localClaimSet.put("iss", this.getIss());
        }
        if(this.getIat() > 0) {
            localClaimSet.put("iat", this.getIat());
        }
        if (this.getQsh() != null && this.getQsh().length() >0) {
            localClaimSet.put("qsh", this.getQsh());
        }
        if (this.getSub() != null && this.getSub().length() >0) {
            localClaimSet.put("sub", this.getSub());
        }
        return localClaimSet;
    }


}
