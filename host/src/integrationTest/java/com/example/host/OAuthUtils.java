package com.example.host;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Stolen (and modified) from
 * https://github.com/mark-hoogenboom/spring-boot-oauth-testing/blob/master/src/test/java/com/robinfinch/oslo/test/OAuthUtils.java
 *
 * H/T to Mark Hogenboom, whose medium article (https://medium.com/@mark.hoogenboom/testing-a-spring-boot-application-secured-by-oauth-e40d1e9a6f60)
 * inspired these unit and integration tests.
 *
 * TODO: include MIT license anc copyright notice
 */
public class OAuthUtils {

    public static OAuth2User createOAuth2User(String name, String email) {

        Map<String, Object> authorityAttributes = new HashMap<>();
        authorityAttributes.put("key", "value");

        //GrantedAuthority authority = new OAuth2UserAuthority(authorityAttributes);
        List<GrantedAuthority> authorityList = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_A");
        //OAuth2UserAuthority authority = new OAuth2UserAuthority(authorityAttributes);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "1234567890");
        attributes.put("name", name);
        attributes.put("email", email);

        //return new DefaultOAuth2User(asList(authority), attributes, "sub");
        return new DefaultOAuth2User(authorityList, attributes, "sub");
    }

    public static Authentication getOauthAuthenticationFor(OAuth2User principal) {

        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();

        String authorizedClientRegistrationId = "my-oauth-client";

        return new OAuth2AuthenticationToken(principal, authorities, authorizedClientRegistrationId);
    }
}
