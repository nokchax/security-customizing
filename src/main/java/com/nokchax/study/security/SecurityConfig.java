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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
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
                .authorizationEndpoint()
                .authorizationRequestResolver(new OAuth2AuthorizationRequestResolver() {
                    // request에 대해서 oauth 에 사용될 request로 변환해 주는 작업을 하는 클래스.
                    // oauth login 에서 parameter 를 사용한다면, 값을 추출하기에 제일 적합? 깔끔하다.

                    @Override
                    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                        return null;
                    }

                    @Override
                    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                        return null;
                    }
                })
                .and()
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
                .logoutUrl("") // 로그아웃을 실행하는 필터와 매칭되는 url
                .addLogoutHandler((request, response, authentication) -> {}) // 로그아웃 처리를 직접 하고 싶을때 list로 되어 있기 때문에 교체가 아닌 추가!
                .clearAuthentication(true) // 인증정보를 지움
                .deleteCookies("delete cookie") // varargs 를 받으므로 쿠키명 사이에 공백을 넣어 여러 쿠키를 지울 수 있다.
                .logoutRequestMatcher(request -> true) //todo logout url 과의 차이점은??
                .logoutSuccessUrl("") // 로그아웃 성공 이후 리다이렉트 할 url
                .logoutSuccessHandler((request, response, authentication) -> {}); // 로그아웃 성공 이후에 부가 작업을 추가하기 위함
        
        
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
        // 혹은 userDetails 에 커스텀 유저를 사용해보기 (결국 저장하는건 userDetails 이기 때문)
        // 단, 이후에 load 시에는 UserNamePasswordAuthenticationToken 으로 통일해도 문제없는지 테스트가 필요
        // 
        //

        // Twitter 를 SpringSecurity 와 Twitter4j 로 구현하기
        // http.apply(customConfigurer) 를 사용해서 추가
        // RedirectFilter 와 AuthenticatedFilter 그리고 AuthenticationProvider 를 커스터마이징 해야한다.
        
        // RedirectFilter 는 Oauth1 요청에 첫 단계를 위한 필터로 
        // 회원의 requestToken 을 생성하고 이를 twitter server 측에 전달하는 역할을 한다.
        
        // AuthenticationProvider 는 Twitter 로그인 이후에 다시 리다이렉트 되는 url와 매칭되어 oauthverifier 와 requestToken을 가지고
        // 앱과 twitter api 사이의 통신을 통해 사용자의 정보를 획득한다..
        
        // AuthenticatedFilter 는 AuthenticationProvider 와 각종 handler 등을 포함한 추상 클래스로
        // 커스터마이징 한 AuthenticatedFilter 는 TwitterOauthToken 이라는 Authentication 을 임시로 생성하고 이를
        // AuthenticationProvider 에 넘겨주는 역할, 이후 Authentication (TwitterOauthToken) 을 받아서 성공 혹은 실패 처리를 진행한다.
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
    // 
}
