package com.couchbase.client.encryption.errors;

public class CryptoProviderMissingPrivateKeyException extends Exception {

	public CryptoProviderMissingPrivateKeyException() {
		super();
	}

	public CryptoProviderMissingPrivateKeyException(String message) {
		super(message);
	}
}
