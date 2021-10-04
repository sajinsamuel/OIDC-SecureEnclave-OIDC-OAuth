package com.example.enclave;

import com.nimbusds.jwt.JWT;

import java.util.MissingResourceException;

public class RequestHandler extends VerifierEnclave{

    @Override
    protected void handleMessage(byte[] message, JWT token) throws IllegalArgumentException, SecurityException, MissingResourceException, UnsupportedOperationException {
        System.out.println(new String(message));
    }

}
