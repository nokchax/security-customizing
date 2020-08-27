package com.nokchax.study.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityApplication {

    /*
     * 시작점 @SpringBootApplication
     * -> AutoConfigurationPackages
     * -> SpringBootWebSecurityConfiguration
     * -> WebSecurityConfigurerAdapter // 여기서 설정 시작
     */
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
