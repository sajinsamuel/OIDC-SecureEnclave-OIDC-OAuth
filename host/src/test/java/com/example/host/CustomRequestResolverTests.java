package com.example.host;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import static org.mockito.Mockito.*;

/**
 * Should test that, upon CustomizationRequestResolver.resolve()
 * the setAuthorizationRequestCustomizer() is called,
 * THEN the resolve() method of the passed-in DefaultOAuth2AuthorizationRequestResolver
 * is called.
 *
 * Also, verifies that the customizer Consumer passed to setAuthorizationRequestCustomizer()
 * performs the correct operation; namely, it sets the attribute and nonce parameter to what
 * is expected.
 *
 * Together, assuming that the DefaultOAuth2AuthorizationRequestResolver
 * works as expected, this should mean that the entire class works as expected.
 *
 * NOTE that this test is "brittle"; it relies on an implementation strategy
 * (the use of setAuthorizationRequestCustomizer) which isn't necessarily the only way
 * to do this and is not (supposed to be) guaranteed through the "contract" of this class.
 * This means that a valid, creative implementation in the future may break this test.
 */
public class CustomRequestResolverTests {
    /*
    sample pubkey:
    secret

    sample nonce (sha256 of "secret"):
    K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols
    */

    DefaultOAuth2AuthorizationRequestResolver mockResolver;
    CustomizationRequestResolver customResolver;

    /**
     * Initialize the mock reslover and our own custom resolver,
     * which we will use in all subsequent tests
     */
    @BeforeEach
    public void setup() {
        // the mock default resolver
        // TODO make this a field
        mockResolver = mock(DefaultOAuth2AuthorizationRequestResolver.class);

        // our own custom resolver, which uses the mock resolver
        customResolver = new CustomizationRequestResolver(mockResolver);
    }

    /**
     * Test that the resolve() method of the passed-in
     * DefaultOAuth2AuthorizationRequestResolver is called.
     */
    @Test
    public void testResolveCalled() {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("pubkey", "secret");

        customResolver.resolve(mockHttpServletRequest);
        verify(mockResolver).resolve(mockHttpServletRequest);
    }

    /**
     * Test that the setAuthorizationRequestCustomizer() method of the passed-in
     * DefaultOAuth2AuthorizationRequestResolver is called before
     * the resolve() method
     */
    @Test
    public void testCustomizerSet() {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("pubkey", "secret");

        customResolver.resolve(mockHttpServletRequest);

        // make sure stuff happens in order
        InOrder inOrder = inOrder(mockResolver);

        inOrder.verify(mockResolver).setAuthorizationRequestCustomizer(any());
        inOrder.verify(mockResolver).resolve(mockHttpServletRequest);
        inOrder.verifyNoMoreInteractions();

    }

    /**
     * Test that the returned OAuth2AuthorizationRequest
     * has its nonce attribute (which will not be sent to the IDP)
     * set to the public key of the user (in this case, "secret")
     */
    @Test
    public void testReturnedRequestAttribute() {
        ArgumentCaptor<Consumer<OAuth2AuthorizationRequest.Builder>>
                customizer = ArgumentCaptor.forClass(Consumer.class);

        // make a test request
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("pubkey", "secret");

        customResolver.resolve(mockHttpServletRequest);

        verify(mockResolver).setAuthorizationRequestCustomizer(customizer.capture());
        OAuth2AuthorizationRequest.Builder builder = TestOAuth2AuthorizationRequests.oidcRequest();
        customizer.getValue().accept(builder);

        OAuth2AuthorizationRequest builtRequest = builder.build();
        assert(builtRequest.getAttribute(OidcParameterNames.NONCE).equals("secret"));
    }

    /**
     * Test that the returned OAuth2AuthorizationRequest has its "nonce" property
     * (which will be sent to the IDP) set to "K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols"
     * (which is the sha256 hash of "secret")
     */
    @Test
    public void testReturnedRequestParameter() {
        ArgumentCaptor<Consumer<OAuth2AuthorizationRequest.Builder>>
                customizer = ArgumentCaptor.forClass(Consumer.class);

        // make a test request
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("pubkey", "secret");

        customResolver.resolve(mockHttpServletRequest);

        verify(mockResolver).setAuthorizationRequestCustomizer(customizer.capture());
        OAuth2AuthorizationRequest.Builder builder = TestOAuth2AuthorizationRequests.oidcRequest();
        customizer.getValue().accept(builder);

        OAuth2AuthorizationRequest builtRequest = builder.build();
        assert(builtRequest.getAdditionalParameters().get("nonce")
                .equals("K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols"));
    }


    /**
     * Static class to generate valid OAuth2AuthorizationRequest.Builder s
     * to test pubkeyInNonce().
     *
     * Stolen from
     * https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-core/src/test/java/org/springframework/security/oauth2/core/endpoint/TestOAuth2AuthorizationRequests.java
     */
    public static final class TestOAuth2AuthorizationRequests {

        private TestOAuth2AuthorizationRequests() {
        }

        public static OAuth2AuthorizationRequest.Builder request() {
            String registrationId = "registration-id";
            String clientId = "client-id";
            Map<String, Object> attributes = new HashMap<>();
            attributes.put(OAuth2ParameterNames.REGISTRATION_ID, registrationId);
            // @formatter:off
            return OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri("https://example.com/login/oauth/authorize")
                    .clientId(clientId)
                    .redirectUri("https://example.com/authorize/oauth2/code/registration-id")
                    .state("state")
                    .attributes(attributes);
            // @formatter:on
        }

        public static OAuth2AuthorizationRequest.Builder oidcRequest() {
            return request().scope("openid");
        }

    }
}
