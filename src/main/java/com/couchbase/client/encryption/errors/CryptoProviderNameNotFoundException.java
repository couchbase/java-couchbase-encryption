package com.couchbase.client.encryption.errors;


public class CryptoProviderNameNotFoundException extends Exception {

	public CryptoProviderNameNotFoundException() {
		super();
	}

	public CryptoProviderNameNotFoundException(String message) {
		super(message);
	}
}
