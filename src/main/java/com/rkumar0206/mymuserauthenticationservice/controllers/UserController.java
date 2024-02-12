package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.PasswordResetRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserDetailsRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserEmailRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.TokenResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import com.rkumar0206.mymuserauthenticationservice.utlis.ModelMapper;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Optional;

import static com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants.ACCESS_TOKEN;
import static com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants.REFRESH_TOKEN;
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
    public ResponseEntity<CustomResponse<UserAccountResponse>> getUserDetails(@RequestHeader("correlation-id") String correlationId) {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        try {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserAccount userAccount = userService.getUserByEmailId(authentication.getPrincipal().toString());

            if (userAccount == null) {
                response.setStatus(HttpStatus.NO_CONTENT.value());
                throw new UserException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
            }

            response.setStatus(HttpStatus.OK.value());
            response.setMessage(Constants.SUCCESS);
            response.setBody(ModelMapper.buildUserAccountResponse(userAccount));

            log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, "User details fetching successful"));

        } catch (RuntimeException e) {

            MymUtil.setAppropriateResponseStatus(response, e, correlationId);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PostMapping("/create")
    public ResponseEntity<CustomResponse<UserAccountResponse>> createUser(@RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestBody UserAccountRequest userAccountRequest) {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        try {

            if (!userAccountRequest.isValid()) {
                throw new UserException(ErrorMessageConstants.INVALID_USER_DETAILS_ERROR);
            }

            UserAccountResponse accountResponse = userService.createUser(userAccountRequest);

            response.setStatus(HttpStatus.CREATED.value());
            response.setMessage(String.format(Constants.SUCCESS_, "User created successfully. Please check your email for email verification."));
            response.setBody(accountResponse);

            log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, "User created successfully."));

        } catch (Exception ex) {

            MymUtil.setAppropriateResponseStatus(response, ex, correlationId);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PutMapping("/update/basic")
    public ResponseEntity<CustomResponse<UserAccountResponse>> updateBasicUserDetails(@RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestBody UpdateUserDetailsRequest updateUserDetailsRequest) {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        try {

            if (!updateUserDetailsRequest.isValid()) {
                throw new UserException(ErrorMessageConstants.INVALID_USER_DETAILS_FOR_UPDATE_ERROR);
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserAccount userAccount = userService.getUserByEmailId(authentication.getPrincipal().toString());

            if (userAccount == null) {
                response.setStatus(BAD_REQUEST.value());
                response.setMessage(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
            } else {

                UserAccountResponse userAccountResponse = userService.updateUserBasicDetails(updateUserDetailsRequest);

                response.setStatus(HttpStatus.OK.value());
                response.setMessage(String.format(Constants.SUCCESS_, "User details updated successfully."));
                response.setBody(userAccountResponse);

                log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, "User details updated successfully."));
            }

        } catch (Exception ex) {

            MymUtil.setAppropriateResponseStatus(response, ex, correlationId);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PutMapping("/update/email")
    public ResponseEntity<CustomResponse<String>> updateUserEmailRequest(@RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestBody UpdateUserEmailRequest updateUserEmailRequest) {

        CustomResponse<String> response = new CustomResponse<>();

        try {

            if (!updateUserEmailRequest.isValid()) {
                throw new UserException(ErrorMessageConstants.INVALID_USER_DETAILS_FOR_UPDATE_ERROR);
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserAccount userAccount = userService.getUserByEmailId(authentication.getPrincipal().toString());

            if (userAccount == null) {
                response.setStatus(BAD_REQUEST.value());
                response.setMessage(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
            } else {

                userService.updateUserEmailId(updateUserEmailRequest);

                response.setStatus(HttpStatus.OK.value());
                response.setMessage(Constants.SUCCESS);
                response.setBody("An OTP has been sent to your new email-id which is valid only for 10 minutes, please verify.");
            }

        } catch (Exception ex) {

            MymUtil.setAppropriateResponseStatus(response, ex, correlationId);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PostMapping("/update/email/verify/otp")
    public ResponseEntity<CustomResponse<TokenResponse>> verifyOTPForEmailUpdate(HttpServletResponse httpServletResponse, @RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestParam String otp) {

        CustomResponse<TokenResponse> response = new CustomResponse<>();

        try {

            if (MymUtil.isNotValid(otp) || otp.trim().length() != 6) {
                throw new UserException(ErrorMessageConstants.OTP_NOT_VALID);
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserAccount userAccount = userService.getUserByEmailId(authentication.getPrincipal().toString());

            if (userAccount == null) {
                response.setStatus(BAD_REQUEST.value());
                response.setMessage(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
            } else {

                UserAccount updatedUserAccount = userService.verifyOTPAndUpdateEmail(otp);

                TokenResponse token = new TokenResponse(jwtUtil.generateAccessToken(updatedUserAccount), jwtUtil.generateRefreshToken(updatedUserAccount));

                response.setStatus(HttpStatus.OK.value());
                response.setMessage(Constants.SUCCESS);
                response.setBody(token);

                // add access token and refresh token in cookies
                MymUtil.addAuthTokensToCookies(httpServletResponse, jwtUtil.generateAccessToken(updatedUserAccount), jwtUtil.generateRefreshToken(updatedUserAccount));
            }

        } catch (Exception ex) {

            MymUtil.setAppropriateResponseStatus(response, ex, correlationId);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PutMapping("/password/reset")
    public ResponseEntity<CustomResponse<String>> passwordResetAuthenticated(@RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestBody PasswordResetRequest passwordResetRequest) {

        CustomResponse<String> response = new CustomResponse<>();

        try {
            if (!passwordResetRequest.isValid()) {
                throw new UserException(ErrorMessageConstants.INVALID_PASSWORD_RESET_REQUEST);
            }

            userService.resetPassword(passwordResetRequest);

            response.setStatus(HttpStatus.OK.value());
            response.setMessage(Constants.SUCCESS);
            response.setBody("Password is changed for this user.");

        } catch (Exception e) {

            MymUtil.setAppropriateResponseStatus(response, e, correlationId);
        }
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<CustomResponse<String>> forgotPassword(@RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestParam("email") String email) {

        CustomResponse<String> response = new CustomResponse<>();

        try {

            if (MymUtil.isNotValid(email) || !MymUtil.isEmailStringValid(email)) {
                throw new UserException(ErrorMessageConstants.EMAIL_ID_INVALID);
            }

            userService.sendPasswordResetUrlToEmailIdForForgotPassword(email);

            response.setStatus(HttpStatus.OK.value());
            response.setMessage(Constants.SUCCESS);
            response.setBody("Please check your email for password reset");
        } catch (Exception e) {

            MymUtil.setAppropriateResponseStatus(response, e, correlationId);
        }
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }


    @GetMapping("/account/verify")
    public ResponseEntity<CustomResponse<String>> verifyEmail(@RequestParam("token") String token) {

        CustomResponse<String> response = new CustomResponse<>();

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(token);

        switch (accountVerificationMessage) {
            case VERIFIED, ALREADY_VERIFIED -> {
                response.setMessage(accountVerificationMessage.getValue());
                response.setStatus(HttpStatus.OK.value());
            }
            case INVALID -> {

                response.setMessage(accountVerificationMessage.getValue());
                response.setStatus(HttpStatus.BAD_REQUEST.value());
            }
        }

        return new ResponseEntity<>(response, HttpStatus.valueOf(response.getStatus()));
    }

    @GetMapping("/token/refresh")
    public ResponseEntity<CustomResponse<TokenResponse>> refreshToken(HttpServletRequest request, @RequestHeader(Constants.CORRELATION_ID) String correlationId, @RequestParam("uid") String uid) {

        CustomResponse<TokenResponse> response = new CustomResponse<>();

        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(Constants.BEARER)) {

            String token = MymUtil.getTokenFromAuthorizationHeader(authorizationHeader);

            try {

                UserAccount userAccount = verifyToken(token);

                if (!userAccount.getUid().equals(uid)) {
                    throw new RuntimeException(ErrorMessageConstants.PERMISSION_DENIED);
                }
                response.setStatus(HttpStatus.OK.value());
                response.setMessage(Constants.SUCCESS);
                response.setBody(TokenResponse.builder().access_token(jwtUtil.generateAccessToken(userAccount)).refresh_token(token).build());

                log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, "New access-token generated through refresh token"));

            } catch (Exception e) {
                response.setStatus(FORBIDDEN.value());
                response.setMessage(e.getMessage());

                log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, e.getMessage()));
            }

        } else {

            response.setStatus(BAD_REQUEST.value());
            response.setMessage(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID);
            log.info(String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID));
        }
        return new ResponseEntity<>(response, HttpStatus.valueOf(response.getStatus()));
    }

    @GetMapping("/token/refresh/cookie")
    public ResponseEntity<String> refreshToken(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();

        Optional<Cookie> refreshTokenCookie = Arrays.stream(cookies).filter(c -> c.getName().equals(Constants.REFRESH_TOKEN)).findFirst();

        try {

            if (refreshTokenCookie.isEmpty()) {
                throw new RuntimeException("Refresh token not found in cookies");
            }

            String refreshToken = refreshTokenCookie.get().getValue();

            UserAccount userAccount = verifyToken(refreshToken);

            String accessToken = jwtUtil.generateAccessToken(userAccount);

            // added tokens in cookies
            MymUtil.addAuthTokensToCookies(response, accessToken, refreshToken);

            //added tokens in header
            response.setHeader(ACCESS_TOKEN, accessToken);
            response.setHeader(REFRESH_TOKEN, refreshToken);

            return ResponseEntity.ok("Token successfully added to cookies");

        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<CustomResponse<String>> logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {

        CookieClearingLogoutHandler cookieClearingLogoutHandler = new CookieClearingLogoutHandler(
                ACCESS_TOKEN, REFRESH_TOKEN
        );

        cookieClearingLogoutHandler.logout(request, response, authentication);

        CustomResponse<String> mResponse = new CustomResponse<>(
                HttpStatus.OK.value(), Constants.SUCCESS, "Logout successful"
        );

        return new ResponseEntity<>(mResponse, HttpStatus.OK);
    }

    private UserAccount verifyToken(String token) {
        DecodedJWT decodedJWT = jwtUtil.isTokenValid(token);

        Claim tokenTypeClaim = decodedJWT.getClaim(Constants.TOKEN_TYPE);

        if (tokenTypeClaim.isMissing() || tokenTypeClaim.isNull() || !tokenTypeClaim.asString().equals(Constants.REFRESH_TOKEN))
            throw new RuntimeException(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID);

        String username = decodedJWT.getSubject();
        UserAccount userAccount = userService.getUserByEmailId(username);

        if (userAccount == null) throw new RuntimeException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);

        if (!userAccount.isAccountVerified())
            throw new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR);

        return userAccount;
    }
}
