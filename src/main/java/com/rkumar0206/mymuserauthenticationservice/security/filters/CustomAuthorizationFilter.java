package com.rkumar0206.mymuserauthenticationservice.security.filters;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.Utility;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JWT_Util jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (Utility.getServletPathsForWhichNoAuthenticationIsRequired().contains(request.getServletPath())) {

            log.info("no authorization required for servlet path : " + request.getServletPath());

            filterChain.doFilter(request, response);
        } else {

            String authHeader = request.getHeader(AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith(Constants.BEARER)) {

                try {

                    String token = authHeader.substring(Constants.BEARER.length());

                    log.info("Received Token : " + token);
                    log.info("Checking if token is expired or invalid...");

                    DecodedJWT decodedToken = jwtUtil.isTokenValid(token);

                    String emailId = decodedToken.getSubject();
                    String uid = decodedToken.getClaim("uid").asString();

                    if (uid == null) {
                        throw new RuntimeException("Invalid access token");
                    }

                    String keyId = decodedToken.getKeyId();

                    if (!StringUtils.hasLength(uid.trim()) && !StringUtils.hasLength(keyId.trim()))
                        throw new RuntimeException("Token invalid");

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(emailId, null, new ArrayList<>());

                    // this indicates that the user is successfully authorized
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                    log.info("Token is valid. User successfully authorized...");

                    filterChain.doFilter(request, response);
                } catch (Exception ex) {

                    log.info("Token is invalid, reason : " + ex.getMessage());

                    response.setHeader(Constants.ERROR, ex.getMessage());
                    response.setStatus(HttpStatus.FORBIDDEN.value());

                    Map<String, String> error = new HashMap<>();
                    error.put(Constants.ERROR, ex.getMessage());

                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }

            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
