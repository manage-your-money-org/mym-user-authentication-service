package com.rkumar0206.mymuserauthenticationservice.security.filters;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
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

        if (MymUtil.getServletPathsForWhichNoAuthenticationIsRequired().contains(request.getServletPath())) {

            log.info("no authorization required for servlet path : " + request.getServletPath());

            filterChain.doFilter(request, response);
        } else {

            // check if token is sent through cookies, and if not then check if authorization header is present in
            // the request or not and if not then send appropriate error response

            boolean isTokenReceivedInCookie = handleTokenReceivedInCookies(request, response, filterChain);

            if (!isTokenReceivedInCookie) {

                handleTokenReceivedAsHeader(request, response, filterChain);
            }
        }
    }

    private void handleTokenReceivedAsHeader(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String authHeader = request.getHeader(AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith(Constants.BEARER)) {

            try {

                String token = authHeader.substring(Constants.BEARER.length());
                checkTokenAndAuthorizeUser(token);
                filterChain.doFilter(request, response);
            } catch (Exception ex) {

                log.info("Access Token is invalid, reason : " + ex.getMessage());
                sendNotAuthorizedResponse(response, ex);
            }

        } else {
            filterChain.doFilter(request, response);
        }
    }

    private boolean handleTokenReceivedInCookies(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        boolean isTokenReceivedInCookie = false;

        Cookie[] cookies = request.getCookies();

        if (cookies != null) {

            Map<String, String> tokens = new HashMap<>();

            for (Cookie cookie : cookies) {

                if (cookie.getName().equals(Constants.ACCESS_TOKEN)) {
                    isTokenReceivedInCookie = true;
                    tokens.put(Constants.ACCESS_TOKEN, cookie.getValue());
                }

                if (cookie.getName().equals(Constants.REFRESH_TOKEN)) {
                    tokens.put(Constants.REFRESH_TOKEN, cookie.getValue());
                }

                if (tokens.size() == 2) {
                    break;
                }
            }

            if (isTokenReceivedInCookie && tokens.size() == 2) {

                try {
                    checkTokenAndAuthorizeUser(tokens.get(Constants.ACCESS_TOKEN));
                    filterChain.doFilter(request, response);
                } catch (JWTVerificationException e) {

                    log.info("Access token received in cookies is expired or invalid: " + e.getMessage());

                    if (e.getMessage().startsWith("The Token has expired")) {
                        // the token is expired
                        generateNewAccessTokenUsingRefreshTokenAndAuthenticateUser(response, tokens);
                        filterChain.doFilter(request, response);
                    }
                }
            }
        }
        return isTokenReceivedInCookie;
    }

    private void generateNewAccessTokenUsingRefreshTokenAndAuthenticateUser(HttpServletResponse response, Map<String, String> tokens) throws IOException {

        try {

            log.info("Generating new access token using the refresh token received in cookies");

            DecodedJWT decodedRefreshToken = jwtUtil.isTokenValid(tokens.get(Constants.REFRESH_TOKEN));
            Claim tokenTypeClaim = decodedRefreshToken.getClaim(Constants.TOKEN_TYPE);

            if (tokenTypeClaim.isMissing() || tokenTypeClaim.isNull() || !tokenTypeClaim.asString().equals(Constants.REFRESH_TOKEN))
                throw new RuntimeException(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID);

            String username = decodedRefreshToken.getSubject();
            // create new access token and authenticate user
            User user = new User(username, "this_value_will_not_be_used", new ArrayList<>());
            String newAccessToken = jwtUtil.generateAccessToken(user);
            // add tokens to cookies
            MymUtil.addAuthTokensToCookies(response, newAccessToken, tokens.get(Constants.REFRESH_TOKEN));

            log.info("Access token successfully generated and added to cookies");

            authorizeUser(username);
        } catch (JWTVerificationException ex) {

            log.info("Refresh token is invalid, reason : " + ex.getMessage());
            sendNotAuthorizedResponse(response, ex);
        }
    }

    private void checkTokenAndAuthorizeUser(String token) throws JWTVerificationException {

        log.info("Received Token : " + token);
        log.info("Checking if token is expired or invalid...");

        DecodedJWT decodedToken = jwtUtil.isTokenValid(token);

        String emailId = decodedToken.getSubject();

        String keyId = decodedToken.getKeyId();

        if (!StringUtils.hasLength(keyId.trim()))
            throw new RuntimeException("Token invalid");

        log.info("Token valid...");

        authorizeUser(emailId);
    }

    private void authorizeUser(String emailId) {

        log.info("Authorizing user...");

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(emailId, null, new ArrayList<>());

        // this indicates that the user is successfully authorized
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

        log.info("User successfully authorized...");
    }

    private void sendNotAuthorizedResponse(HttpServletResponse response, Exception ex) throws IOException {

        response.setHeader(Constants.ERROR, ex.getMessage());
        response.setStatus(HttpStatus.FORBIDDEN.value());

        Map<String, String> error = new HashMap<>();
        error.put(Constants.ERROR, ex.getMessage());

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
