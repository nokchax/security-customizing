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
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

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

        // set multiple authentication provider
        // https://www.baeldung.com/spring-security-multiple-auth-providers
        // https://stackoverflow.com/questions/35363924/java-spring-security-config-multiple-authentication-providers
        // customize authentication provider
        http.authenticationProvider(new CustomAuthenticationProvider());


        // customizing new authentication filter
        // https://jeong-pro.tistory.com/205
        // AbstractAuthenticationProcessingFilter 를 구현하면 된다.

        // Oauth2.0LoginAuthenticationFilter 내부 로직 summary
        // authentication manager 는 authentication provider 리스트를 가지고 있고 리스트를 순회하면서 support 하는 authentication provider 를 가지고 authentication 을 생성한다
        // RequestMatcher requiresAuthenticationRequestMatcher; 를 통해 해당 Filter를 적용할지 말지 판단하게 되므로 이쪽도 커스터 마이징 해야한다.
        //
        // OAuth2AuthorizationRequestRedirectFilter redirect 를 위한 필터
        // >> Twitter 를 위한 RedirectFilter 도 필요
        // >> Twitter 용 CustomProcessingFilter 구현
        // >> Twitter 용 CustomAuthenticationProvider 구현
        //
        // Oauth2.0 커스터 마이징
        // userOauth2.0Provider 내부에
        // OAuth2UserService<OAuth2UserRequest, OAuth2User> userService; 를 통해 api와 통신하여 사용자 정보 로드
        // https://jeong-pro.tistory.com/205 기본 DefaultOAuth2UserService를 주입 받는 커스텀 UserService를 만들어서 DB에 반영하도록!
        // 
        // Oauth2.0AuthenticationProvider 커스터 마이징 하기
        // OAuth2.0AuthenticationToken 대신 UserNamePasswordAuthenticationToken 을 생성해서 리턴하기 X -> AuthenticationProvider 를 한 번 감싸고 있는 총괄 클래스가 존재하므로 안됨
        // 혹은 userDetails 에 커스텀 유저를 사용해보기 
        // 
        // 

    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring() // 스프링 시큐리티 필터 체인을 타지 않도록 하기 위해서는 ignoring()에 추가해야한다.
                .antMatchers("/css/**", "/js/**", "/images/**", "favicon.ico");
    }


    // ssl 적용하기
    // cert.pem cert.key -> keystore.p12 프로젝트 root에 저장
    // openssl pkcs12 -export -out keystore.p12 -in cert.pem -inkey cert.key
    //
    // spring boot properties 에 적용하기
    // server:
    //  ssl:
    //    key-store: keystore.p12
    //    key-store-password: pw
    //    key-store-type: PKCS12
    //  port: 443


    // oauth2.0 customizing
    // client 등록
    // provider 가 없는 경우 등록 (구글, 페이스북 등은 존재함 하지만 카카오는 등록해야함)
    // AuthenticationProvider 추가해서 Oauth2.0 Token 을 가지고 후처리
}
