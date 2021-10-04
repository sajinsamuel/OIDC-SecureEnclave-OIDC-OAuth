package com.example.host;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@AutoConfigureMockMvc
class OidcServerApplicationTests {

	@Autowired
	MockMvc mockMvc;

    private WireMockServer wireMockServer;

    @BeforeEach
	public void setup() {
    	wireMockServer = new WireMockServer(wireMockConfig().port(8090).extensions(CaptureStateTransformer.class));
    	wireMockServer.start();

    	// Garbage collection go brrrrr

        stubFor(get(urlPathMatching("/oauth/authorize.*"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://localhost:8080/login/oauth2/code/my-oauth-client?code=my-acccess-code&state=${state}")
                        .withTransformers("CaptureStateTransformer")
                )
        );

        stubFor(post(urlPathMatching("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"my-access-token\"" +
                                ", \"token_type\":\"Bearer\"" +
                                ", \"expires_in\":\"3600\"" +
                                "}")
                )
        );

        stubFor(get(urlPathMatching("/userinfo"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"sub\":\"my-user-id\"" +
                                ",\"name\":\"Mark Hoogenboom\"" +
                                ", \"email\":\"mark.hoogenboom@example.com\"" +
                                "}")
                )
        );

    }

    /*
    // this is Junit5--@Rules don't apply!
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().port(8090)
			.extensions(CaptureStateTransformer.class)
     */

    /*
	@Autowired
	private MockMvc mockMvc;
     */

    // TODO: check that proper beans are generated // set up a Mock OAuth server

    //  (is this class really worthy of a unit test?)

	// All of the below should be in integration test folder, not unit test
	@Test
	void contextLoads() {
	}

	@Test
	public void authenticatedUserSendingMail() throws Exception {
		// user should successfully send mail to the enclave, need some enclave feedback?
        // user sends messages to /user/message
        mockMvc.perform((RequestBuilder) get("/user"))
		.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

	}

	@Test
	public void authenticatedUserPubkeyMismatch() {
		// same as above, but the Mail should be generated with a different key than in id token
	}

	@Test
	public void modifiedTokenShouldFail() {
		// e.g. host injects its own public key into the token state, should fail at enclave
		// due to the token not matching its signature
		// token header should be accessed through oauth2login().tokenEndpoint.accessTokenResponseClient()
	}

}
