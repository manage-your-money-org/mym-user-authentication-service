package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.TokenResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.ModelMapper;
import com.rkumar0206.mymuserauthenticationservice.utlis.Utility;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

import static com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants.FAILED_;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
@RequestMapping("/mym/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final JWT_Util jwtUtil;

    @GetMapping("/details")
    public ResponseEntity<CustomResponse<UserAccountResponse>> getUserDetails() {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        try {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserAccount userAccount = userService.getUserByEmailId(authentication.getPrincipal().toString());

            if (userAccount == null) {
                response.setCode(HttpStatus.NO_CONTENT.value());
                throw new UserException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
            }

            response.setCode(HttpStatus.OK.value());
            response.setMessage("Success");
            response.setBody(ModelMapper.buildUserAccountResponse(userAccount));

        } catch (RuntimeException e) {

            if (response.getCode() == 0) {
                response.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
            response.setMessage(String.format(FAILED_, e.getMessage()));
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }

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

            response.setCode(HttpStatus.BAD_REQUEST.value());
            response.setMessage(String.format(Constants.FAILED_, ErrorMessageConstants.INVALID_USER_DETAILS_ERROR));
            log.info("Invalid user details sent for creating user.\n" + userAccountRequest);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }

    @GetMapping("/account/verify")
    public ResponseEntity<CustomResponse<String>> verifyEmail(@RequestParam("token") String token) {

        CustomResponse<String> response = new CustomResponse<>();

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(token);

        switch (accountVerificationMessage) {
            case VERIFIED, ALREADY_VERIFIED -> {
                response.setMessage(accountVerificationMessage.getValue());
                response.setCode(HttpStatus.OK.value());
            }
            case INVALID -> {

                response.setMessage(accountVerificationMessage.getValue());
                response.setCode(HttpStatus.BAD_REQUEST.value());
            }
        }

        return new ResponseEntity<>(response, HttpStatus.valueOf(response.getCode()));
    }

    @GetMapping("/token/refresh")
    public ResponseEntity<CustomResponse<TokenResponse>> refreshToken(HttpServletRequest request, @RequestParam("uid") String uid) throws IOException {

        CustomResponse<TokenResponse> response = new CustomResponse<>();

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
                    throw new RuntimeException(ErrorMessageConstants.PERMISSION_DENIED);
                }

                if (!userAccount.isAccountVerified())
                    throw new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR);

                response.setCode(HttpStatus.OK.value());
                response.setMessage("Success");
                response.setBody(
                        TokenResponse.builder()
                                .access_token(jwtUtil.generateAccessToken(userAccount))
                                .refresh_token(token)
                                .build()
                );

            } catch (Exception e) {

                e.printStackTrace();

                response.setCode(FORBIDDEN.value());
                response.setMessage(e.getMessage());
            }

        } else {

            response.setCode(BAD_REQUEST.value());
            response.setMessage(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID);
        }
        return new ResponseEntity<>(response, HttpStatus.valueOf(response.getCode()));
    }
}
