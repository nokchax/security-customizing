package com.nokchax.study.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityApplication {

    // security architecture doc
    // https://spring.io/guides/topicals/spring-security-architecture

    /*
     * 시작점 @SpringBootApplication
     * -> EnableAutoConfiguration
     * -> AutoConfigurationPackages
     * -> SpringBootWebSecurityConfiguration
     * -> WebSecurityConfigurerAdapter // 여기서 설정 시작
     *      -> 시큐리티를 커스터마이징 할때도 이 클래스를 상속하는 방식을 이용함
     *      -> WebSecurityConfiguration 가 하는 일은???
     *      -> Congifuration을 가지고 SpringSecurityFilterChain을 생성한다 이 객체의 타입은 Filter
     *      -> webSecurityExpressionHandler에서 
     * -> 
     */

    /*
     * StandardWrapperValve (org.apache.catalina.core)
     *  - ApplicationFilterChain 을 가지고 있음
     *  - dispatch 전에 위의 필터 체인을 실행
     *  - dispatch 넌 어느 시점에 들어가는가..?
     *
     */
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
