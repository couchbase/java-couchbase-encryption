package com.couchbase.client.encryption.errors;

public class CryptoProviderMissingPublicKeyException extends Exception {

	public CryptoProviderMissingPublicKeyException() {
		super();
	}

	public CryptoProviderMissingPublicKeyException(String message) {
		super(message);
	}
}
