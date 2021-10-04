package com.example.host;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.function.Consumer;

public class CustomizationRequestResolver
        implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    public CustomizationRequestResolver(
            ClientRegistrationRepository repo,
            String authorizationRequestBaseUri
    ) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
                repo,
                authorizationRequestBaseUri
        );

        //System.out.println("NEW CustomizationRequestResolver CREATED!!!");
        //System.out.println(repo.findByRegistrationId("google").getRegistrationId());
    }

    public CustomizationRequestResolver(
            DefaultOAuth2AuthorizationRequestResolver defaultResolver
    ) {
        this.defaultResolver = defaultResolver;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String pub_key = request.getParameter("pubkey");
        defaultResolver.setAuthorizationRequestCustomizer(pubkeyInNonce(pub_key));
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);
        System.out.println("resolving request with custom resolver");
        //System.out.println("additional parameters: " + req.getAdditionalParameters());
        if (req != null) {
            System.out.println("additional parameters: " + req.getAdditionalParameters());
            System.out.println("attribute nonce: " + req.getAttribute(OidcParameterNames.NONCE));
            try {
                System.out.println(checkHashMatches(req)
                        ? "Hash of " + req.getAttribute(OidcParameterNames.NONCE)
                            + " is " + req.getAdditionalParameters().get("nonce")
                        : "Nonce hash doesn't match");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return req;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        String pub_key = request.getParameter("pubkey");
        defaultResolver.setAuthorizationRequestCustomizer(pubkeyInNonce(pub_key));
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);
        return req;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> pubkeyInNonce(String pub_key) {
        return customizer ->
        {
            customizer.attributes(params -> params.put(OidcParameterNames.NONCE, pub_key))
            .additionalParameters(params -> {
                try {
                    params.put("nonce", createHash(pub_key));
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            });
        };
    }

    private boolean checkHashMatches(OAuth2AuthorizationRequest req) throws NoSuchAlgorithmException {
        String nonceHash = createHash(req.getAttribute(OidcParameterNames.NONCE));
        String nonceHashClaim = (String) req.getAdditionalParameters().get("nonce");
        return nonceHash.equals(nonceHashClaim);
    }

    static String createHash(String nonce) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

}

