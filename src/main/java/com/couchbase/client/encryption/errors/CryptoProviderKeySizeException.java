package com.couchbase.client.encryption.errors;

public class CryptoProviderKeySizeException extends Exception {

	public CryptoProviderKeySizeException() {
		super();
	}

	public CryptoProviderKeySizeException(String message) {
		super(message);
	}
}
