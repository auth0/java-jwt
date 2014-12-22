package com.auth0.jwt;

public class JWTVerifyException extends Exception {
    /**
	 * 
	 */
	private static final long serialVersionUID = -4911506451239107610L;

	public JWTVerifyException() {
    }
	
	

    public JWTVerifyException(String message, Throwable cause) {
		super(message, cause);
	}


	public JWTVerifyException(String message) {
        super(message);
    }
}
