package com.nokchax.study.security.twitter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 트위터 로그인 정보로 만든 인증 요청 토큰을 가지고 시큐리티에서 실제로 활용하는 인증 토큰을 생성하는 필터
public class TwitterAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    protected TwitterAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        return null;
    }
}
