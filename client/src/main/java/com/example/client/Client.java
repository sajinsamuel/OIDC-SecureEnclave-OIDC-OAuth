package com.example.client;

import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.mail.Curve25519PrivateKey;
import com.r3.conclave.mail.PostOffice;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.security.PrivateKey;

public class Client {
    public static void main(String[] args) throws IOException {
        OkHttpClient client = new OkHttpClient();

        Request attestationRequest = new Request.Builder()
                .url("http://localhost:8080/attestation")
                .build();
        Response attestationResponse = client.newCall(attestationRequest).execute();
        EnclaveInstanceInfo attestation
                = EnclaveInstanceInfo.deserialize(attestationResponse.body().bytes());
        System.out.println("Client received attestation!");
        System.out.println(attestation.toString());

        // generate my private keys, etc
        PrivateKey privateKey = Curve25519PrivateKey.random();

        PostOffice postOffice = attestation.createPostOffice(privateKey, "ambiguouscommands");
        // TODO System.out.println(localhost:8080/oauth2/authorization/google?pubkey=12345abcxyz)
        //  this can be pasted into the browser, so the user authenticates there
        //  System.out.println every get request, info should be url-encoded.

        System.out.println("localhost:8080/oauth2/authorization/google?pubkey="
            + postOffice.getSenderPublicKey()
        );
    }
}
