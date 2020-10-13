package com.nokchax.study.security.twitter;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

// twitter accessToken 과 secretToken 을 가지고 twitter api를 호출하여 사용자 정보를 가지고오는 역할을 한다.
public class TwitterAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // tiwtter4j 를 이용해서 사용자 정보를 가지고 온다.
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TwitterOauth1RequestToken.class.isAssignableFrom(authentication);
    }
}
