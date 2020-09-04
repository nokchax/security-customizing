package com.nokchax.study.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring() // 스프링 시큐리티 필터 체인을 타지 않도록 하기 위해서는 ignoring()에 추가해야한다.
                .antMatchers("/css/**", "/js/**", "/images/**", "favicon.ico");
    }
}
