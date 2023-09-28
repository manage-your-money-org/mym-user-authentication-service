package com.rkumar0206.mymuserauthenticationservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "token")
public class TokenConfig {

    private int accessExpirationTimeDay;
    private int refreshExpirationTimeDay;
    private String issuer;
    private String secret;

}
