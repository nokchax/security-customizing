package com.nokchax.study.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/* Authentication (Token) 에 따라 인증을 처리하고 인증된 authentication 을 리턴한다 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    // principal: id / credential: pw
    // credential 을 포함한 완전히 인증된 authentication 객체를 리턴한다.
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 인증을 처리할 수 없는 경우 null 을 리턴하면 되며, 이럴 경우 다음 AuthenticationProvider 에 의해 처리된다. (물론 provider 가 지원 할 때의 얘기)

        // TODO: 2020/09/07 전달 받는 token 과 리턴하는 authentication 간의 차이는 무엇일까?
        return null;
    }

    // 전달 받은 authentication 에 대한 인증을 지원하는지를 리턴함
    // DaoAuthenticationProvider 에서는 UserNamePasswordAuthenticationToken 을 지원하며
    // AuthenticationToken 은 Authentication 을 구현하는 구현체이다.
    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
