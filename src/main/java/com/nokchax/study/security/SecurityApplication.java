package com.nokchax.study.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityApplication {

    /*
     * 시작점 @SpringBootApplication
     * -> EnableAutoConfiguration
     * -> AutoConfigurationPackages
     * -> SpringBootWebSecurityConfiguration
     * -> WebSecurityConfigurerAdapter // 여기서 설정 시작
     *      -> 시큐리티를 커스터마이징 할때도 이 클래스를 상속하는 방식을 이용함
     *      -> WebSecurityConfiguration 가 하는 일은???
     * -> 
     */
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
