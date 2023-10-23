package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.model.request.PasswordResetRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserDetailsRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserEmailRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.TokenResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Date;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;
    @Mock
    private JWT_Util jwtUtil;
    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private UserController userController;

    private void mockSecurityContextAndAuthentication() {
        Authentication authentication = new UsernamePasswordAuthenticationToken("test@gmail.com", null);
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);

        Mockito.when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
    }


    @Test
    void getUserDetails_UserIsAuthorized_Success() {

        UserAccount user = new UserAccount("jbd", "test@gmail.com", "password", "rrrrr", "Rohit", false, "", new Date(), new Date());

        Mockito.when(userService.getUserByEmailId(anyString())).thenReturn(user);

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserDetails(UUID.randomUUID().toString());

        assertEquals(200, response.getStatusCode().value());
        assertEquals("Rohit", response.getBody().getBody().getName());
    }

    @Test
    void getUserDetails_UserNotAvailable_NO_CONTENT_Response() {

        Mockito.when(userService.getUserByEmailId(anyString())).thenReturn(null);

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserDetails(UUID.randomUUID().toString());

        assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatusCode().value());
    }

    @Test
    void getUserDetails_ExceptionOccurred_INTERNAL_SERVER_ERROR_Response() {

        Mockito.when(userService.getUserByEmailId(anyString())).thenThrow(new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR));

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserDetails(UUID.randomUUID().toString());

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatusCode().value());
    }

    @Test
    void createUser_Success() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "test@gmail.com", "password"
        );

        UserAccountResponse userAccountResponse = new UserAccountResponse(
                userAccountRequest.getName(), userAccountRequest.getEmailId(), UUID.randomUUID().toString(), false, new Date(), new Date()
        );

        Mockito.when(userService.createUser(userAccountRequest)).thenReturn(userAccountResponse);

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(UUID.randomUUID().toString(), userAccountRequest);

        assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());
        assertEquals(userAccountRequest.getName(), response.getBody().getBody().getName());
    }

    @Test
    void createUser_RequestNotValid_BAD_REQUEST_RESPONSE() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "", "password"
        );

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(UUID.randomUUID().toString(), userAccountRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
    }

    @Test
    void createUser_ExceptionOccurred_INTERNAL_SERVER_ERROR_RESPONSE() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "test@gmail.com", "password"
        );

        Mockito.when(userService.createUser(userAccountRequest)).thenThrow(new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR));

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(UUID.randomUUID().toString(), userAccountRequest);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatusCode().value());
    }


    @Test
    void verifyEmail_Success() {

        AccountVerificationMessage accountVerificationMessage = AccountVerificationMessage.VERIFIED;

        Mockito.when(userService.verifyEmail(anyString())).thenReturn(accountVerificationMessage);

        ResponseEntity<CustomResponse<String>> response = userController.verifyEmail("sjbksbsb");

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        assertEquals(accountVerificationMessage.getValue(), response.getBody().getMessage());
    }

    @Test
    void verifyEmail_AlreadyVerified_Success() {

        AccountVerificationMessage accountVerificationMessage = AccountVerificationMessage.ALREADY_VERIFIED;

        Mockito.when(userService.verifyEmail(anyString())).thenReturn(accountVerificationMessage);

        ResponseEntity<CustomResponse<String>> response = userController.verifyEmail("sjbksbsb");

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        assertEquals(accountVerificationMessage.getValue(), response.getBody().getMessage());
    }

    @Test
    void verifyEmail_InvalidToken_BAD_REQUEST_Response() {

        AccountVerificationMessage accountVerificationMessage = AccountVerificationMessage.INVALID;

        Mockito.when(userService.verifyEmail(anyString())).thenReturn(accountVerificationMessage);

        ResponseEntity<CustomResponse<String>> response = userController.verifyEmail("sjbksbsb");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertEquals(accountVerificationMessage.getValue(), response.getBody().getMessage());
    }


    @Test
    void refreshToken_Success() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, "", new Date(), new Date()
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateRefreshToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));
        when(jwtUtil.generateAccessToken(userAccount)).thenReturn(jwtUtilTestHelper.generateAccessToken(userAccount));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), userAccount.getUid());

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        assertNotNull(response.getBody().getBody().getAccess_token());
        assertNotNull(response.getBody().getBody().getRefresh_token());
    }

    @Test
    void refreshToken_WrongTokenProvided_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, "", new Date(), new Date()
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateAccessToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), userAccount.getUid());

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID, response.getBody().getMessage());

    }

    @Test
    void refreshToken_UserNotFound_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, "", new Date(), new Date()
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateRefreshToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(null);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), userAccount.getUid());

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.USER_NOT_FOUND_ERROR, response.getBody().getMessage());

    }


    @Test
    void refreshToken_UserTryingToAccessOtherAccount_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, "", new Date(), new Date()
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateRefreshToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), "jbcscbjbsbsjbj");

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.PERMISSION_DENIED, response.getBody().getMessage());

    }

    @Test
    void refreshToken_AccountNotVerified_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", false, "", new Date(), new Date()
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateRefreshToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), userAccount.getUid());

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR, response.getBody().getMessage());

    }

    @Test
    void refreshToken_NoAuthorizationTokenPassed_BAD_REQUEST_Response() throws IOException {

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn(null);

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, UUID.randomUUID().toString(), "jkbbjsksbk");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID, response.getBody().getMessage());

    }


    @Test
    void updateBasicUserDetails_Success() {

        UpdateUserDetailsRequest updateUserDetailsRequest = new UpdateUserDetailsRequest(
                "rohit kumar singh"
        );

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(UserAccount.builder().emailId("shsjhbjhsbjhsb").name("knkskns").build());

        when(userService.updateUserBasicDetails(updateUserDetailsRequest)).thenReturn(
                UserAccountResponse.builder().emailId("sdnjsnk").name(updateUserDetailsRequest.getName()).build()
        );

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.updateBasicUserDetails("xcnkjsnksn", updateUserDetailsRequest);

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
    }

    @Test
    void updateBasicUserDetails_requestNotValid_BAD_REQUEST_Response() {

        UpdateUserDetailsRequest updateUserDetailsRequest = new UpdateUserDetailsRequest(
                null
        );

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.updateBasicUserDetails("xcnkjsnksn", updateUserDetailsRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.INVALID_USER_DETAILS_FOR_UPDATE_ERROR));

    }

    @Test
    void updateBasicUserDetails_NoAccountFound_BAD_REQUEST_Response() {

        UpdateUserDetailsRequest updateUserDetailsRequest = new UpdateUserDetailsRequest(
                "rohit kumar singh"
        );

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(null);


        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.updateBasicUserDetails("xcnkjsnksn", updateUserDetailsRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.USER_NOT_FOUND_ERROR));

    }


    @Test
    void updateUserEmailRequest_Success() throws JsonProcessingException {

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                "rohit@gmail.com"
        );

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(UserAccount.builder().emailId("test@gmail.com").name("knkskns").build());

        doNothing().when(userService).updateUserEmailId(updateUserEmailRequest);

        ResponseEntity<CustomResponse<String>> response = userController.updateUserEmailRequest("sdnsknk", updateUserEmailRequest);

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
    }

    @Test
    void updateUserEmailRequest_RequestNotValid_BAD_REQUEST_Response() throws JsonProcessingException {

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                ""
        );

        ResponseEntity<CustomResponse<String>> response = userController.updateUserEmailRequest("sdnsknk", updateUserEmailRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.INVALID_USER_DETAILS_FOR_UPDATE_ERROR));

    }

    @Test
    void updateUserEmailRequest_UserNotFound_BAD_REQUEST_Response() throws JsonProcessingException {

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                "rohit@gmail.com"
        );

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(null);


        ResponseEntity<CustomResponse<String>> response = userController.updateUserEmailRequest("sdnsknk", updateUserEmailRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.USER_NOT_FOUND_ERROR));

    }


    @Test
    void verifyOTPForEmailUpdate_Success() {

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(UserAccount.builder().emailId("vjhvvhvjvv").name("hjhjvvj").build());

        UserAccount userAccount = UserAccount.builder().emailId("hgvgvhgv").name("hgvvh").build();
        when(userService.verifyOTPAndUpdateEmail(anyString())).thenReturn(userAccount);

        when(jwtUtil.generateAccessToken(userAccount)).thenReturn(new JWT_UtilTestHelper().generateAccessToken(
                userAccount
        ));
        when(jwtUtil.generateRefreshToken(userAccount)).thenReturn(new JWT_UtilTestHelper().generateRefreshToken(userAccount));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.verifyOTPForEmailUpdate("dshjcsjhb", "564754");

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        assertNotNull(response.getBody().getBody().getAccess_token());
        assertNotNull(response.getBody().getBody().getRefresh_token());

    }

    @Test
    void verifyOTPForEmailUpdate_OTPNOtValid_BAD_REQUEST_Response() {


        ResponseEntity<CustomResponse<TokenResponse>> response = userController.verifyOTPForEmailUpdate("dshjcsjhb", "56475");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.OTP_NOT_VALID));

    }

    @Test
    void verifyOTPForEmailUpdate_UserNOtFound_BAD_REQUEST_Response() {

        mockSecurityContextAndAuthentication();

        when(userService.getUserByEmailId(anyString())).thenReturn(null);

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.verifyOTPForEmailUpdate("dshjcsjhb", "564754");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.USER_NOT_FOUND_ERROR));

    }


    @Test
    void passwordResetAuthenticated_Success() {

        PasswordResetRequest passwordResetRequest = new PasswordResetRequest(
                "oldPassword", "newPassword"
        );

        doNothing().when(userService).resetPassword(passwordResetRequest);

        ResponseEntity<CustomResponse<String>> response = userController.passwordResetAuthenticated("dshjcsjhb", passwordResetRequest);

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
    }

    @Test
    void passwordResetAuthenticated_InvalidRequest_BAD_REQUEST_RESPONSE() {

        PasswordResetRequest passwordResetRequest = new PasswordResetRequest(
                null, "newPassword"
        );

        ResponseEntity<CustomResponse<String>> response = userController.passwordResetAuthenticated("dshjcsjhb", passwordResetRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.INVALID_PASSWORD_RESET_REQUEST));

    }

    @Test
    void forgotPassword_Success() throws JsonProcessingException {

        doNothing().when(userService).sendPasswordResetUrlToEmailIdForForgotPassword(anyString());

        ResponseEntity<CustomResponse<String>> response = userController.forgotPassword("dshjcsjhb", "test123@test.com");

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
    }

    @Test
    void forgotPassword_InvalidRequest_BAD_REQUEST_RESPONSE() {

        ResponseEntity<CustomResponse<String>> response = userController.forgotPassword("dshjcsjhb", "invalidemailformat");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertThat(response.getBody().getMessage(), containsString(ErrorMessageConstants.EMAIL_ID_INVALID));

    }
}