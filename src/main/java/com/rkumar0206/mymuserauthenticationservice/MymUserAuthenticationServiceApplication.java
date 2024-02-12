package com.rkumar0206.mymuserauthenticationservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class MymUserAuthenticationServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(MymUserAuthenticationServiceApplication.class, args);
    }

    @Bean
    public BCryptPasswordEncoder getbCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public ObjectMapper getObjectMapperBean() {
		return new ObjectMapper();
	}
}
