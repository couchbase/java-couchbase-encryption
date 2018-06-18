package com.couchbase.client.encryption.errors;

public class CryptoProviderEncryptFailedException extends Exception {

	public CryptoProviderEncryptFailedException() {
		super();
	}

	public CryptoProviderEncryptFailedException(String message) {
		super(message);
	}
}
