package com.nokchax.study.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.util.Collection;

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


        // exception 처리 / 인증에 대해서 처리를 커스터마이징 할 수 있다.
        http.exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> {})
                .accessDeniedPage("/deniedPage")
                .authenticationEntryPoint((request, response, authException) -> {});
        
        // form 로그인 커스터 마이징
        http.formLogin()
                .loginPage("")
                .passwordParameter("")
                .usernameParameter("")
                .successHandler((request, response, authentication) -> {})
                .successForwardUrl("")
                .failureHandler((request, response, exception) -> {})
                .failureUrl("")
                .failureForwardUrl("")
                .authenticationDetailsSource(context -> null);
        
        // logout 커스터 마이징
        http.logout()
                .logoutUrl("")
                .addLogoutHandler((request, response, authentication) -> {})
                .clearAuthentication(true)
                .deleteCookies("delete cookie")
                .logoutRequestMatcher(request -> true)
                .logoutSuccessUrl("")
                .logoutSuccessHandler((request, response, authentication) -> {});
        
        
        // form 로그인시에 username 으로 해당 유저에 대한 User 정보를 리턴하기 위한 service 객체를 커스터 마이징 가능
        http.userDetailsService(username -> new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return null;
            }

            @Override
            public boolean isAccountNonExpired() {
                return false;
            }

            @Override
            public boolean isAccountNonLocked() {
                return false;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return false;
            }

            @Override
            public boolean isEnabled() {
                return false;
            }
        });
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring() // 스프링 시큐리티 필터 체인을 타지 않도록 하기 위해서는 ignoring()에 추가해야한다.
                .antMatchers("/css/**", "/js/**", "/images/**", "favicon.ico");
    }


}
