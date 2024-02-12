package com.rkumar0206.mymuserauthenticationservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "routing-keys")
public class RoutingKeysConfig {

    private String accountVerification;
    private String emailUpdateOtp;
    private String passwordReset;
}
