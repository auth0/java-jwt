package com.auth0.jwt;

public class ClaimSet {

	private int exp;
	
	public int getExp() {
		return exp;
	}

	public void setExp(int exp) {
		this.exp = (int)(System.currentTimeMillis() / 1000L) + exp;
	}
}
