package com.rkumar0206.mymuserauthenticationservice.security.config;

import com.rkumar0206.mymuserauthenticationservice.security.filters.CustomAuthenticationFilter;
import com.rkumar0206.mymuserauthenticationservice.security.filters.CustomAuthorizationFilter;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWT_Util jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(getAuthenticationManagerBean(), jwtUtil);
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
                            "/mym/api/users/token/refresh/cookie",
                            "/mym/api/users/password/forgot",
                            "/mym/api/users/password/reset/form",
                            "/mym/api/users/password/reset/form/submit",
                            "/mym/mym-user-authentication-service/actuator/**"
                    ).permitAll();
                    auth.anyRequest().authenticated();
                })
                .cors(AbstractHttpConfigurer::disable)
                .addFilterAfter(new CustomAuthorizationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .addFilter(customAuthenticationFilter)
                .build();

    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity httpSecurity) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);

        DaoAuthenticationConfigurer<AuthenticationManagerBuilder, UserDetailsService> daoAuthenticationConfigurer = authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);

        return daoAuthenticationConfigurer.and().build();
    }

    public AuthenticationManager getAuthenticationManagerBean() throws Exception {

        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:4200"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
