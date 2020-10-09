package com.nokchax.study.security.twitter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class TwitterOAuth1Token extends AbstractAuthenticationToken {

    public TwitterOAuth1Token(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
    // 사용자 정보를 로드한 이후에 사용되는 토큰
}
