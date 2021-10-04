package com.example.host;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;


@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // TODO: Get rid of Autowired and instead use a constructor,
    //  as autowiring should happen anyway but this allows for unit testing
    //  NOTE: it seems that this may not be possible yet (https://stackoverflow.com/questions/35845106/is-constructor-injection-possible-in-spring-configuration-classes)
    //  Due to a bug.
    //  Maybe just hold off on unit-testing this?

    @Autowired
    ClientRegistrationRepository registrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // require all requests to be authenticated
                .authorizeRequests(authorize -> authorize
                    .antMatchers("/user/**").authenticated())

                // this is how the oauth login will happen
                .oauth2Login()
                // configure the endpoint
                .authorizationEndpoint(
                        authorizationEndpoint ->
                                // add our own resolver; this changes parameters sent in the code as we like
                                authorizationEndpoint.authorizationRequestResolver(
                                        new CustomizationRequestResolver(
                                                new DefaultOAuth2AuthorizationRequestResolver(
                                                        registrationRepository,
                                                        "/oauth2/authorization"
                                                )

                                        )
                                )

                );

    }

}
