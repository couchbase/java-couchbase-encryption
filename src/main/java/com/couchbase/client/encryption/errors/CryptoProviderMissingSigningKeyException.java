package com.couchbase.client.encryption.errors;

public class CryptoProviderMissingSigningKeyException extends Exception {

	public CryptoProviderMissingSigningKeyException() {
		super();
	}

	public CryptoProviderMissingSigningKeyException(String message) {
		super(message);
	}
}
