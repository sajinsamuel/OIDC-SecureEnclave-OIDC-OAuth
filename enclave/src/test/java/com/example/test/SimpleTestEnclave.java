package com.example.test;

import com.example.enclave.VerifierEnclave;
import com.nimbusds.jwt.JWT;

import java.util.MissingResourceException;

public class SimpleTestEnclave extends VerifierEnclave {

    @Override
    protected void handleMessage(byte[] message, JWT token) throws IllegalArgumentException, SecurityException, MissingResourceException, UnsupportedOperationException {
        postMail(message, "unencrypted message");
    }

}
