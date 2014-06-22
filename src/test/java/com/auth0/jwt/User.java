package com.auth0.jwt;

/**
 * Sample object for serialization
 */
public class User {

	private String username;
	private String password;
	
	public User() {
	}
	
	public String getUsername() {
		return username;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public String getPassword() {
		return password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
}
