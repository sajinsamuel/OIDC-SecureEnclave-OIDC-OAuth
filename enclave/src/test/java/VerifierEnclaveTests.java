import com.example.enclave.VerifierEnclave;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.common.SHA256Hash;
import com.r3.conclave.host.AttestationParameters;
import com.r3.conclave.host.EnclaveHost;
import com.r3.conclave.host.EnclaveLoadException;
import com.r3.conclave.host.MailCommand;
import com.r3.conclave.mail.Curve25519PrivateKey;
import com.r3.conclave.mail.PostOffice;
//import com.r3.conclave.testing.MockHost;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.SerializationUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.MissingResourceException;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierEnclaveTests {
    // valid OIDC token:
    // "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFiZjhhODRkM2VjZDc3ZTlmMmFkNWYwNmZmZDI2MDcwMWRkMDZkOTAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMDU2MzI1MjAzOTIxMjcyOTgiLCJlbWFpbCI6ImRzaHRlaW5ib2tAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJOQjdwRmZva0RCUGNIbm1JQm1OaDBRIiwibm9uY2UiOiJLN2dOVTNzZG8tT0wwd05ocW9WV2hyM2c2czF4WXY3Mm9sX3BlX1Vub2xzIiwibmFtZSI6IkRhbmllbCBTaHRlaW5ib2siLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R2pXWDJRU0gtSjFLY01ZSko5U3Jrc09Bd3NxdTYwTlU4elNTSW0xPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkRhbmllbCIsImZhbWlseV9uYW1lIjoiU2h0ZWluYm9rIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2MjYyOTExMzksImV4cCI6MTYyNjI5NDczOX0.cV4E2lIt4-gQLmjBFuL8xi8QLOcLhbIKJwuTDuJ_KXHKtnQ5ENvm_qJfdzWkwk1SR2ggAAS10oAS-Ub0fJ7YYTzbNfftDoC9TYki4ERLlTdBZuojiEOMwnbwYrF683f-XXVi93xmOLioyG8YkC3wuYHuZ6kjq8ZPAzFvF-yXgUYo6xfSMjtyjCqqljJj00KjElRxV6g73dG5EtdYoy_pW_htPPYp9h30FAbenKEIePGI963ToKY4SEqNpcYgkhVkfJ98bA0bxzm9csdrvuCBq62WgzElWj_S9f4EPOFsrNWHLLxdwee08AdgMI3d7JXwPQsYSV8K-Fvvd2Q9qoVUIw"

    private EnclaveHost enclaveHost;
    public AtomicReference<byte[]> mailToSend;
    static class SimpleEnclave extends VerifierEnclave {
        // hold a counter field that allows us to keep track of how many times handleMessage is called
            /*
            private int counter = 0;



            public int getCounter() {
                return counter;
            }

             */
        public SimpleEnclave() {
            super();
        }

        @Override
        protected void handleMessage(byte[] message, JWT token) throws IllegalArgumentException, SecurityException, MissingResourceException, UnsupportedOperationException {
            // increment counter each time handleMessage is called,
            // so we can track how many times handleMessage is called
            //counter += 1;
        }
    }
    @BeforeEach
    public void makeEnclave() throws EnclaveLoadException {
        // load the enclave from the module
        enclaveHost = EnclaveHost.load("com.example.test.SimpleTestEnclave");

        // initialize mailToSend
        mailToSend = new AtomicReference<>();



        // STARTING THE ENCLAVE

        // ensure that all mail coming out of the enclave is put into mailToSend
        // which can be accessed from all the other tests
        enclaveHost.start(new AttestationParameters.DCAP(), (commands) -> {
            for (MailCommand command : commands) {
                if (command instanceof MailCommand.PostMail) {
                    mailToSend.set(((MailCommand.PostMail) command).getEncryptedBytes());
                }
            }
        });


    }

    /**
     * Test that a valid message, encrypted with a valid secret key,
     * and sent with a valid id token gets processed in the way that is expected.
     *
     * Should test that
     * - mockHandler is called as we expect (message matches mail, name matches id token that we pass)
     * - returns the mail that we expect (passes back the same response it gets from mockHandler)
     */
    @Test
    public void testHappyCaseReturnedMail() throws IOException, ParseException {
        // Set secret key
        // secret key = Curve25519PrivateKey(SHA256.hash("secret".getBytes()).getBytes)
        // public key encoded: a946160f377bc3591cd0224bcc38ec120f2c16ab7705ccdb3ddff372c89e7e24
        // appropriate id token:
        // eyJhbGciOiJSUzI1NiIsImtpZCI6IjFiZjhhODRkM2VjZDc3ZTlmMmFkNWYwNmZmZDI2MDcwMWRkMDZkOTAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMDU2MzI1MjAzOTIxMjcyOTgiLCJlbWFpbCI6ImRzaHRlaW5ib2tAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiI0Qy05aFRSdE1pMk1ub0pNdU9Uakx3Iiwibm9uY2UiOiJURGlYSHVGSE4weTUwWlEtelplMHBZOVFUbjdXSHVQSVZ1Nko1c19KbWVrIiwibmFtZSI6IkRhbmllbCBTaHRlaW5ib2siLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R2pXWDJRU0gtSjFLY01ZSko5U3Jrc09Bd3NxdTYwTlU4elNTSW0xPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkRhbmllbCIsImZhbWlseV9uYW1lIjoiU2h0ZWluYm9rIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2MjYzNTg0NjYsImV4cCI6MTYyNjM2MjA2Nn0.lEKdWX6d9YrYX6fnuzzl_S-gJF_Pk3-7W3ekbJLZQJnJB8iWW8qAV7j_tcxDmIb9h3H3qAXHmbStuuayJSwnRYEDgF8-oYhXdaYV22tiCL8MbGOLKjZaOzinSENJirrhuBiYvvl4IrMFxHlXl46oPJWhaNbfsFUMT_q7PG6R7BjikajXM9zj1qVe4UP-DNdvXngImgnH_XBkJI5akwP3lEmJdzU5qD0_spTRliKN2OHWRFCxB3mEY9ctrlBX65Lb1EARrCpQ4KeXA4M_aEQS3mrg1GzFiVHc2lRhPaMwgkwhpn8Aj4-LuaW4j33R5tO1y2WSTQuT9MKeRyGQmTf09Q

        // Get attestation
        // Encrypt mail
        // Send mail with pre-generated id token code

        // generate the secret key from a known value
        // the value from which the secretKey is generated must be 256 bits, so we use a SHA256 hash
        PrivateKey secretKey = new Curve25519PrivateKey(
                SHA256Hash.hash("secret".getBytes(StandardCharsets.UTF_8)).getBytes()
        );

        final String id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFiZjhhODRkM2VjZDc3ZTlmMmFkNWYwNmZm" +
                "ZDI2MDcwMWRkMDZkOTAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZ" +
                "S5jb20iLCJhenAiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuY" +
                "XBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN" +
                "3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwM" +
                "DU2MzI1MjAzOTIxMjcyOTgiLCJlbWFpbCI6ImRzaHRlaW5ib2tAZ21haWwuY29tIiwiZW1haWxfdmVya" +
                "WZpZWQiOnRydWUsImF0X2hhc2giOiI0Qy05aFRSdE1pMk1ub0pNdU9Uakx3Iiwibm9uY2UiOiJURGlYS" +
                "HVGSE4weTUwWlEtelplMHBZOVFUbjdXSHVQSVZ1Nko1c19KbWVrIiwibmFtZSI6IkRhbmllbCBTaHRla" +
                "W5ib2siLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R" +
                "2pXWDJRU0gtSjFLY01ZSko5U3Jrc09Bd3NxdTYwTlU4elNTSW0xPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6I" +
                "kRhbmllbCIsImZhbWlseV9uYW1lIjoiU2h0ZWluYm9rIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2MjYzN" +
                "Tg0NjYsImV4cCI6MTYyNjM2MjA2Nn0.lEKdWX6d9YrYX6fnuzzl_S-gJF_Pk3-7W3ekbJLZQJnJB8iWW" +
                "8qAV7j_tcxDmIb9h3H3qAXHmbStuuayJSwnRYEDgF8-oYhXdaYV22tiCL8MbGOLKjZaOzinSENJirrhu" +
                "BiYvvl4IrMFxHlXl46oPJWhaNbfsFUMT_q7PG6R7BjikajXM9zj1qVe4UP-DNdvXngImgnH_XBkJI5ak" +
                "wP3lEmJdzU5qD0_spTRliKN2OHWRFCxB3mEY9ctrlBX65Lb1EARrCpQ4Ke" +
                "XA4M_aEQS3mrg1GzFiVHc2lRhPaMwgkwhpn8Aj4-LuaW4j33R5tO1y2WSTQuT9MKeRyGQmTf09Q";

        // Message that we want to send:
        final byte[] message = SerializationUtils.serialize(new String[] {"message"});
        //System.out.println(new String(Hex.encode(message)));
        //final byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        // expected response from stubbed mock
        //final byte[] response = "response".getBytes(StandardCharsets.UTF_8);

        // the test userID that is currently hard-coded into VerifierEnclave
        //final String userId = "Daniel Shteinbok";
        JWT userId = JWTParser.parse(id_token);


        // the attestation we get from the enclave, which contains its public key
        EnclaveInstanceInfo attestation = enclaveHost.getEnclaveInstanceInfo();

        // encrypt our message using our private key and the enclave's public key
        PostOffice postOffice = attestation.createPostOffice(secretKey, "message");
        byte[] encryptedMessage = postOffice.encryptMail(message);

        // this is the same hex-encoded encrypted message we will use when performing full manual integration tests
        System.out.println(Hex.encode(encryptedMessage));

        // actually deliver the encrypted message to the enclave the way that the untrusted host would
        enclaveHost.deliverMail(1, encryptedMessage, id_token);

        // Time for verification!
        // here, just check that our mock RequestHandler object's handleMessage() was called with the expected message
        byte[] response = mailToSend.getAndSet(null);
        assertArrayEquals(message, response);
    }

    /**
     * Test that an invalid token throws the error we expect.
     * Ensure that the mockHandler is NOT called for invalid token.
     */
    @Test
    public void testInvalidToken() throws ParseException {
        // no need to generate a secret key or encrypt, since it shouldn't be handled
        final String invalidToken = "eyinvalidtoken";

        /*
        // HAHA! EnclaveHost will try to format the message as EnclaveMail first,
        // and upon failing it will throw a RuntimeException because the mail is corrupt etc.
        // Therefore, need valid mail to test with.

        // [WRONG ASSUMPTION] no need to actually encrypt the message, as it shouldn't be processed
        byte[] encryptedMessage = "encrypted message".getBytes(StandardCharsets.UTF_8);
         */


        PrivateKey secretKey = new Curve25519PrivateKey(
                SHA256Hash.hash("a different secret".getBytes(StandardCharsets.UTF_8)).getBytes()
        );

        final byte[] message = "different message".getBytes(StandardCharsets.UTF_8);

        // the attestation we get from the enclave, which contains its public key
        EnclaveInstanceInfo attestation = enclaveHost.getEnclaveInstanceInfo();

        // encrypt our message using our private key and the enclave's public key
        PostOffice postOffice = attestation.createPostOffice(secretKey, "message");
        byte[] encryptedMessage = postOffice.encryptMail(message);

        // deliver whatever mail we deliver, but with an invalid token
        assertThrows(IllegalArgumentException.class, () -> enclaveHost.deliverMail(1, encryptedMessage, invalidToken));
    }

    /**
     * Token and message are valid,
     * but nonce in token doesn't match the public key used for the mail.
     *
     * ALMOST identical to testHappyCaseReturnedMail,
     * only the secretKey (while still valid) differs, while the token is the same.
     * Therefore, the two do NOT match in this case. An error should be thrown.
     */
    @Test
    public void testPubKeyMismatch() throws ParseException {
        PrivateKey secretKey = new Curve25519PrivateKey(
                SHA256Hash.hash("DIFFERENT secret".getBytes(StandardCharsets.UTF_8)).getBytes()
        );

        final String id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFiZjhhODRkM2VjZDc3ZTlmMmFkNWYwNmZm" +
                "ZDI2MDcwMWRkMDZkOTAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZ" +
                "S5jb20iLCJhenAiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN3Jsb3Roc3BtaGFyMTg1ZzcyaWwuY" +
                "XBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MDA3ODMwOTQwNDYtb2ZibWc5dmpqajNzN" +
                "3Jsb3Roc3BtaGFyMTg1ZzcyaWwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwM" +
                "DU2MzI1MjAzOTIxMjcyOTgiLCJlbWFpbCI6ImRzaHRlaW5ib2tAZ21haWwuY29tIiwiZW1haWxfdmVya" +
                "WZpZWQiOnRydWUsImF0X2hhc2giOiI0Qy05aFRSdE1pMk1ub0pNdU9Uakx3Iiwibm9uY2UiOiJURGlYS" +
                "HVGSE4weTUwWlEtelplMHBZOVFUbjdXSHVQSVZ1Nko1c19KbWVrIiwibmFtZSI6IkRhbmllbCBTaHRla" +
                "W5ib2siLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R" +
                "2pXWDJRU0gtSjFLY01ZSko5U3Jrc09Bd3NxdTYwTlU4elNTSW0xPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6I" +
                "kRhbmllbCIsImZhbWlseV9uYW1lIjoiU2h0ZWluYm9rIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2MjYzN" +
                "Tg0NjYsImV4cCI6MTYyNjM2MjA2Nn0.lEKdWX6d9YrYX6fnuzzl_S-gJF_Pk3-7W3ekbJLZQJnJB8iWW" +
                "8qAV7j_tcxDmIb9h3H3qAXHmbStuuayJSwnRYEDgF8-oYhXdaYV22tiCL8MbGOLKjZaOzinSENJirrhu" +
                "BiYvvl4IrMFxHlXl46oPJWhaNbfsFUMT_q7PG6R7BjikajXM9zj1qVe4UP-DNdvXngImgnH_XBkJI5ak" +
                "wP3lEmJdzU5qD0_spTRliKN2OHWRFCxB3mEY9ctrlBX65Lb1EARrCpQ4Ke" +
                "XA4M_aEQS3mrg1GzFiVHc2lRhPaMwgkwhpn8Aj4-LuaW4j33R5tO1y2WSTQuT9MKeRyGQmTf09Q";

        // Message that we want to send:
        final byte[] message = SerializationUtils.serialize(new String[] {"message"});
        // expected response from stubbed mock
        final byte[] response = "response".getBytes(StandardCharsets.UTF_8);

        // the test userID that is currently hard-coded into VerifierEnclave
        //final String userId = "Daniel Shteinbok";

        // the attestation we get from the enclave, which contains its public key
        EnclaveInstanceInfo attestation = enclaveHost.getEnclaveInstanceInfo();

        // encrypt our message using our private key and the enclave's public key
        PostOffice postOffice = attestation.createPostOffice(secretKey, "message");
        byte[] encryptedMessage = postOffice.encryptMail(message);

        // actually deliver the encrypted message to the enclave the way that the untrusted host would
        assertThrows(IllegalArgumentException.class, () -> enclaveHost.deliverMail(1, encryptedMessage, id_token));

        // ensure that mockHandler is never actually called
    }

}
