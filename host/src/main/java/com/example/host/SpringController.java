package com.example.host;

import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.host.EnclaveHost;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;

@RestController
public class SpringController {

    private EnclaveHost enclave;

    public SpringController(EnclaveHost enclave) {
        this.enclave = enclave;
    }

    @GetMapping("/user")
    public String user(@CurrentSecurityContext SecurityContext securityContext) {
        System.out.println("Current security context authentication details:");
        System.out.println(securityContext.getAuthentication().getDetails());
        System.out.println();

        System.out.println("Current security context authentication principal:");
        System.out.println(securityContext.getAuthentication().getPrincipal());
        System.out.println();

        System.out.println("Current security context authentication credentials:");
        // Returns an empty string
        System.out.println(securityContext.getAuthentication().getCredentials());
        System.out.println();

        System.out.println("Principal type: " + securityContext.getAuthentication().getPrincipal().getClass());
        System.out.println();

        System.out.println("Oidc Token:\n" + ((DefaultOidcUser)
                securityContext.getAuthentication().getPrincipal()).getIdToken().getTokenValue()
        );

        System.out.println("Oidc Token claims:\n"
                + String.join(", ", ((DefaultOidcUser) securityContext.getAuthentication().getPrincipal())
                    .getIdToken().getClaims().keySet())
        );

        return securityContext.getAuthentication().toString();
    }

    @GetMapping(path="/user/message",
            //consumes = MediaType.APPLICATION_JSON_VALUE
            consumes = MediaType.TEXT_PLAIN_VALUE
            //produces = MediaType.APPLICATION_JSON_VALUE
    )
    public byte[] message(@CurrentSecurityContext SecurityContext securityContext, @RequestBody String message) {
        System.out.println("Message endpoint being hit with mail: " + message);
        enclave.deliverMail(1, Hex.decode(message),
                ((DefaultOidcUser) securityContext.getAuthentication().getPrincipal())
                        .getIdToken().getTokenValue());
        // TODO: return a page that has asyncronous javascript to get the resulting mail
        //  when it becomes available
        return null;
    }

    @GetMapping("/attestation")
    public byte[] attestation() {
        // get the enclave's attestation
        EnclaveInstanceInfo attestation = enclave.getEnclaveInstanceInfo();

        // serialize and return it
        return attestation.serialize();
    }
}

