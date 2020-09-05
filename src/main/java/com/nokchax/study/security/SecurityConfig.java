package com.nokchax.study.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 권한 설정
        // antMatcher 와 mvcMatchers 의 차이
        http.authorizeRequests()
                .antMatchers("").anonymous()
                .mvcMatchers("").authenticated()
                .mvcMatchers("").denyAll()
                .mvcMatchers("").fullyAuthenticated()
                .mvcMatchers("").hasAnyAuthority("")
                .mvcMatchers("").hasAnyRole("")
                .mvcMatchers("").hasIpAddress("")
                .mvcMatchers("").hasAuthority("")
                .mvcMatchers("").hasRole("")
                .mvcMatchers("").rememberMe()
                .mvcMatchers("").permitAll()
                .mvcMatchers("").access("")
                .mvcMatchers("").not().hasAnyRole("");

        // 시큐리티 필터 체인 내에 필터 추가
        http.addFilter(new SomeFilter())
                .addFilterAfter(new SomeFilter(), SecurityContextPersistenceFilter.class)
                .addFilterBefore(new SomeFilter(), SecurityContextPersistenceFilter.class)
                .addFilterAt(new SomeFilter(), SecurityContextPersistenceFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring() // 스프링 시큐리티 필터 체인을 타지 않도록 하기 위해서는 ignoring()에 추가해야한다.
                .antMatchers("/css/**", "/js/**", "/images/**", "favicon.ico");
    }


}
