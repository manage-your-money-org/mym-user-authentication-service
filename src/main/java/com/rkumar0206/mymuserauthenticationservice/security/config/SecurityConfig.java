package com.rkumar0206.mymuserauthenticationservice.security.config;

import com.rkumar0206.mymuserauthenticationservice.security.filters.CustomAuthenticationFilter;
import com.rkumar0206.mymuserauthenticationservice.security.filters.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(getAuthenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/mym/app/users/login");

        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(
                            "/mym/app/users/login",
                            "/mym/api/users/create",
                            "/mym/api/users/account/verify",
                            "/mym/api/users/token/refresh",
                            "/mym/api/users/account/forgotPassword",
                            "/mym/api/users/account/passwordReset").permitAll();

                    auth.anyRequest().authenticated();
                })
                .addFilterAfter(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilter(customAuthenticationFilter)
                .build();

    }

    @Bean
    public BCryptPasswordEncoder getbCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity httpSecurity) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);

        DaoAuthenticationConfigurer<AuthenticationManagerBuilder, UserDetailsService> daoAuthenticationConfigurer = authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(getbCryptPasswordEncoder());

        return daoAuthenticationConfigurer.and().build();
    }

    public AuthenticationManager getAuthenticationManagerBean() throws Exception {

        return authenticationConfiguration.getAuthenticationManager();
    }
}
