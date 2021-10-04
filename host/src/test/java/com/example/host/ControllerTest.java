package com.example.host;

import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.host.EnclaveHost;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.nio.charset.StandardCharsets;

import static org.mockito.Mockito.*;
import static org.springframework.test.util.AssertionErrors.assertEquals;

public class ControllerTest {

    private EnclaveHost enclave;
    private SpringController controller;

    @BeforeEach
    public void setup() {
        enclave = mock(EnclaveHost.class);
        controller = new SpringController(enclave);
    }

    @Test
    public void testAttestation() {
        EnclaveInstanceInfo mockEnclaveInstanceInfo = mock(EnclaveInstanceInfo.class);
        when(mockEnclaveInstanceInfo.serialize()).thenReturn("attestation".getBytes(StandardCharsets.UTF_8));

        when(enclave.getEnclaveInstanceInfo()).thenReturn(mockEnclaveInstanceInfo);

        // ensure that the result we got matches what we expected
        assertEquals("assert that attestation response matches actual attestation",
                controller.attestation(), "attestation".getBytes(StandardCharsets.UTF_8));

        // ensure that we had gotten the attestation in the expected manner
        verify(enclave).getEnclaveInstanceInfo();
    }

    @Test
    public void testMessage() {
        // the expected token value
        final String tokenValue = "token value";
        final String message = new String(Hex.encode("message".getBytes(StandardCharsets.UTF_8)));

        // create the mock token we will return, which will return the given tokenValue
        OidcIdToken mockToken = mock(OidcIdToken.class);
        when(mockToken.getTokenValue()).thenReturn(tokenValue);

        DefaultOidcUser principal = mock(DefaultOidcUser.class);
        when(principal.getIdToken()).thenReturn(mockToken);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(principal);

        SecurityContext mockContext = mock(SecurityContext.class);
        when(mockContext.getAuthentication()).thenReturn(authentication);


        controller.message(mockContext, message);
        // TODO: CHANGE THIS! THIS IS SILLY (not every message has id: 1)!
        verify(enclave).deliverMail(1, Hex.decode(message), tokenValue);
    }
}
