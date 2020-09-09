package com.nokchax.study.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

        // oauth2 login customizing
        http.oauth2Login()
                .tokenEndpoint(tokenEndpointConfig -> {})
                .userInfoEndpoint(userInfoEndpointConfig -> {})
                .authorizationEndpoint(authorizationEndpointConfig -> {})
                .authorizedClientRepository(new OAuth2AuthorizedClientRepository() {
                    @Override
                    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request) {
                        return null;
                    }

                    @Override
                    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, HttpServletRequest request, HttpServletResponse response) {

                    }

                    @Override
                    public void removeAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request, HttpServletResponse response) {

                    }
                }).clientRegistrationRepository(registrationId -> null)
                .loginPage("/loginpage")
                .loginProcessingUrl("/processingUrl")
                .redirectionEndpoint(redirectionEndpointConfig -> {})
                .authorizedClientService(new OAuth2AuthorizedClientService() {
                    @Override
                    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
                        return null;
                    }

                    @Override
                    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {

                    }

                    @Override
                    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

                    }
                }).successHandler((request, response, authentication) -> {})
                .failureHandler((request, response, exception) -> {});

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
        
        // about cors
        http.cors();

        // customize authentication provider
        http.authenticationProvider(new CustomAuthenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring() // 스프링 시큐리티 필터 체인을 타지 않도록 하기 위해서는 ignoring()에 추가해야한다.
                .antMatchers("/css/**", "/js/**", "/images/**", "favicon.ico");
    }


}
