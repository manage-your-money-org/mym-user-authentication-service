package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.Utility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/mym/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final JWT_Util jwtUtil;

    @PostMapping("/create")
    public ResponseEntity<CustomResponse<UserAccountResponse>> createUser(
            @RequestBody UserAccountRequest userAccountRequest
    ) {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        if (userAccountRequest.isValid()) {

            try {

                UserAccountResponse accountResponse = userService.createUser(userAccountRequest);

                response.setCode(HttpStatus.CREATED.value());
                response.setMessage(String.format(Constants.SUCCESS_, "User created successfully. Please check you email for email verification."));
                response.setBody(accountResponse);

                log.info("User created successfully");

            } catch (Exception ex) {

                response.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
                response.setMessage(String.format(Constants.FAILED_, ex.getMessage()));

                log.info("Exception occurred while creating user.\n" + ex.getMessage());
            }

        } else {

            response.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setMessage(String.format(Constants.FAILED_, ErrorMessageConstants.INVALID_USER_DETAILS_ERROR));
            log.info("Invalid user details sent for creating user.\n" + userAccountRequest);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }

    @GetMapping("/account/verify")
    public ResponseEntity<CustomResponse<String>> verifyEmail(@RequestParam("token") String token) {

        CustomResponse<String> response = CustomResponse.<String>builder()
                .code(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("Something went wrong")
                .build();

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(token);

        switch (accountVerificationMessage) {
            case VERIFIED -> {
                response.setMessage("Account verified.");
                response.setCode(HttpStatus.OK.value());
            }
            case ALREADY_VERIFIED -> {

                response.setMessage("Account already verified. Please login.");
                response.setCode(HttpStatus.OK.value());
            }
            case INVALID -> {

                response.setMessage("Invalid token.");
                response.setCode(HttpStatus.BAD_REQUEST.value());
            }
        }

        return new ResponseEntity<>(response, HttpStatus.valueOf(response.getCode()));
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response, @RequestParam("uid") String uid) throws IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(Constants.BEARER)) {

            String token = Utility.getTokenFromAuthorizationHeader(authorizationHeader);

            try {

                DecodedJWT decodedJWT = jwtUtil.isTokenValid(token);

                String username = decodedJWT.getSubject();
                UserAccount userAccount = userService.getUserByEmailId(username);

                if (userAccount == null)
                    throw new RuntimeException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);

                if (!userAccount.getUid().equals(uid)) {
                    throw new RuntimeException("Permission denied");
                }

                if (!userAccount.isAccountVerified())
                    throw new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR);

                Map<String, String> tokens = new HashMap<>();
                tokens.put(ACCESS_TOKEN, jwtUtil.generateAccessToken(userAccount));
                tokens.put(REFRESH_TOKEN, token);

                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {

                e.printStackTrace();

                response.setHeader(ERROR, e.getMessage());
                response.setStatus(FORBIDDEN.value());

                Map<String, String> error = new HashMap<>();
                error.put(ERROR, e.getMessage());

                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }


}
