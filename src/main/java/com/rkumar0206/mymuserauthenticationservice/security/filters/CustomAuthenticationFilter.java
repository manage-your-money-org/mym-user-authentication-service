package com.rkumar0206.mymuserauthenticationservice.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants.*;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWT_Util jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = request.getParameter(Constants.USERNAME);
        String password = request.getParameter(Constants.PASSWORD);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        log.info("Authentication successful");

        User user = (User) authResult.getPrincipal();

        String access_token = jwtUtil.generateAccessToken(user);
        String refresh_token = jwtUtil.generateRefreshToken(user);

        log.info("JWT tokens created successfully.");

        response.setHeader(ACCESS_TOKEN, access_token);
        response.setHeader(REFRESH_TOKEN, refresh_token);

        Map<String, String> tokens = new HashMap<>();
        tokens.put(ACCESS_TOKEN, access_token);
        tokens.put(REFRESH_TOKEN, refresh_token);

        CustomResponse<Map<String, String>> customResponse = new CustomResponse<>();

        customResponse.setStatus(HttpStatus.OK.value());
        customResponse.setMessage("Authentication Successful");
        customResponse.setBody(tokens);

        // sending these tokens as HttpOnly cookies
        MymUtil.addAuthTokensToCookies(response, access_token, refresh_token);

        response.setContentType(APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), customResponse);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        //super.unsuccessfulAuthentication(request, response, failed);

        log.info("Authentication un-successful");

        Map<String, String> error = new HashMap<>();
        error.put(ERROR, failed.getMessage());

        CustomResponse<Map<String, String>> customResponse = new CustomResponse<>();

        customResponse.setStatus(HttpStatus.FORBIDDEN.value());
        customResponse.setMessage("Authentication Successful");
        customResponse.setBody(error);

        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        new ObjectMapper().writeValue(response.getOutputStream(), customResponse);
    }
}
