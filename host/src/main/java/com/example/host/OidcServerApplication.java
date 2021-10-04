package com.example.host;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonTypeId;
import com.r3.conclave.common.EnclaveInstanceInfo;
import com.r3.conclave.common.SHA256Hash;
import com.r3.conclave.host.AttestationParameters;
import com.r3.conclave.host.EnclaveHost;
import com.r3.conclave.host.EnclaveLoadException;
import com.r3.conclave.host.MailCommand;
import com.r3.conclave.mail.Curve25519PrivateKey;
import com.r3.conclave.mail.Curve25519PublicKey;
import com.r3.conclave.mail.PostOffice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.config.web.servlet.oauth2.client.OAuth2ClientSecurityMarker;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.SerializationUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicReference;

@SpringBootApplication
public class OidcServerApplication {

	@Bean(destroyMethod = "close")
	public EnclaveHost enclave() throws EnclaveLoadException {
		try {
			EnclaveHost.checkPlatformSupportsEnclaves(true);
			System.out.println("This platform supports enclaves in all three modes");
		} catch (EnclaveLoadException e) {
			System.out.println("This platform only supports simulation");
		}
		String enclaveName = "com.example.enclave.RequestHandler";
		EnclaveHost enclave = EnclaveHost.load(enclaveName);
		//enclave.start(null, null);
		System.out.println("Created enclave");


		// return the created enclave
		return enclave;
	}

	@Bean
	public AtomicReference<byte[]> mailToSend() throws EnclaveLoadException {
	    AtomicReference<byte[]> mailToSend = new AtomicReference<>();
	    enclave().start(new AttestationParameters.DCAP(), (commands) -> {
	    	for (MailCommand command : commands) {
	    		if (command instanceof MailCommand.PostMail) {
	    			mailToSend.set(((MailCommand.PostMail) command).getEncryptedBytes());
				}
			}
		});
		// TODO: remove below (only for testing it out temporarily, just generate some valid mail)
		// print the remote attestation for the enclave, as well as a sample generated mail
		// secret key must match public key we put into initial authorization request
		// (created with "secret" String -> to byte[] -> hashed
		PrivateKey secretKey = new Curve25519PrivateKey(
				SHA256Hash.hash("secret".getBytes(StandardCharsets.UTF_8)).getBytes()
		);
		EnclaveInstanceInfo attestation = enclave().getEnclaveInstanceInfo();
		PostOffice postOffice = attestation.createPostOffice(secretKey, "message");
		System.out.println("public key: " + postOffice.getSenderPublicKey());
		System.out.println("getEncoded: " + new String(Hex.encode(postOffice.getSenderPublicKey().getEncoded())));
		final byte[] message = "test message".getBytes(StandardCharsets.UTF_8);
		System.out.println(Hex.encode(postOffice.encryptMail(message)));

		return mailToSend;
	}

	public static void main(String[] args) {
		SpringApplication.run(OidcServerApplication.class, args);
	}

}
