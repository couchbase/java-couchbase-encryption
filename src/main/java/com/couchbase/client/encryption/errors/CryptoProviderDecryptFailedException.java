package com.couchbase.client.encryption.errors;

public class CryptoProviderDecryptFailedException extends Exception {

	public CryptoProviderDecryptFailedException() {
		super();
	}

	public CryptoProviderDecryptFailedException(String message) {
		super(message);
	}
}
