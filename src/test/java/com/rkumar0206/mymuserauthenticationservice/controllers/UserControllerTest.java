package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
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
    void getUserByUid_UserIsAuthorized_Success() {

        UserAccount user = new UserAccount("jbd", "test@gmail.com", "password", "rrrrr", "Rohit", false, "");

        Mockito.when(userService.getUserByUid(anyString())).thenReturn(user);
        Mockito.when(userService.getUserByEmailId(anyString())).thenReturn(user);

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserByUid("rrrrr");

        assertEquals(200, response.getStatusCode().value());
        assertEquals("Rohit", response.getBody().getBody().getName());
    }

    @Test
    void getUserByUid_NoUID_Passed_BADREQUEST_Response() {

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserByUid("");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
    }

    @Test
    void getUserByUid_UserIsAuthorized_ButTryingToGetInfoAboutOtherUID_FORBIDDEN_Response() {

        UserAccount user1 = new UserAccount("jbd", "test@gmail.com", "password", "rrrrr", "Rohit", false, "");
        UserAccount user2 = new UserAccount("jbd", "test@gmail.com", "password", "mmmmm", "Rohit", false, "");

        Mockito.when(userService.getUserByUid(anyString())).thenReturn(user1);
        Mockito.when(userService.getUserByEmailId(anyString())).thenReturn(user2);

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserByUid("rrrrr");

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
    }

    @Test
    void getUserByUid_UserNotAvailable_NO_CONTENT_Response() {

        Mockito.when(userService.getUserByUid(anyString())).thenReturn(null);
        Mockito.when(userService.getUserByEmailId(anyString())).thenReturn(null);

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserByUid("rrrrr");

        assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatusCode().value());
    }

    @Test
    void getUserByUid_ExceptionOccurred_INTERNAL_SERVER_ERROR_Response() {

        Mockito.when(userService.getUserByUid(anyString())).thenThrow(new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR));

        mockSecurityContextAndAuthentication();

        ResponseEntity<CustomResponse<UserAccountResponse>> response = userController.getUserByUid("rrrrr");

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatusCode().value());
    }

    @Test
    void createUser_Success() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "test@gmail.com", "password"
        );

        UserAccountResponse userAccountResponse = new UserAccountResponse(
                userAccountRequest.getName(), userAccountRequest.getEmailId(), UUID.randomUUID().toString(), false
        );

        Mockito.when(userService.createUser(userAccountRequest)).thenReturn(userAccountResponse);

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(userAccountRequest);

        assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());
        assertEquals(userAccountRequest.getName(), response.getBody().getBody().getName());
    }

    @Test
    void createUser_RequestNotValid_BAD_REQUEST_RESPONSE() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "", "password"
        );

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(userAccountRequest);

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
    }

    @Test
    void createUser_ExceptionOccurred_INTERNAL_SERVER_ERROR_RESPONSE() throws Exception {

        UserAccountRequest userAccountRequest = new UserAccountRequest(
                "Rohit Kumar", "test@gmail.com", "password"
        );

        Mockito.when(userService.createUser(userAccountRequest)).thenThrow(new RuntimeException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR));

        ResponseEntity<CustomResponse<UserAccountResponse>> response =
                userController.createUser(userAccountRequest);

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
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, ""
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateAccessToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));
        when(jwtUtil.generateAccessToken(userAccount)).thenReturn(jwtUtilTestHelper.generateAccessToken(userAccount));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, userAccount.getUid());

        assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        assertNotNull(response.getBody().getBody().getAccess_token());
        assertNotNull(response.getBody().getBody().getRefresh_token());
    }

    @Test
    void refreshToken_UserNotFound_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, ""
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateAccessToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(null);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, userAccount.getUid());

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.USER_NOT_FOUND_ERROR, response.getBody().getMessage());

    }

    @Test
    void refreshToken_UserTryingToAccessOtherAccount_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", true, ""
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateAccessToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, "jbcscbjbsbsjbj");

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.PERMISSION_DENIED, response.getBody().getMessage());

    }

    @Test
    void refreshToken_AccountNotVerified_ForbiddenResponse() throws IOException {

        UserAccount userAccount = new UserAccount(
                "kjkjbjbhs", "rkumar8092378845@gmail.com", "sbksvdvd", "f16f2219eeb64edda90f661a94f6a734", "Rohit Kumar", false, ""
        );


        JWT_UtilTestHelper jwtUtilTestHelper = new JWT_UtilTestHelper();

        String token = jwtUtilTestHelper.generateAccessToken(userAccount);

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn("Bearer " + token);
        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(jwtUtil.isTokenValid(anyString())).thenReturn(jwtUtilTestHelper.isTokenValid(token));

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, userAccount.getUid());

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR, response.getBody().getMessage());

    }

    @Test
    void refreshToken_NoAuthorizationTokenPassed_BAD_REQUEST_Response() throws IOException {

        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn(null);

        ResponseEntity<CustomResponse<TokenResponse>> response = userController.refreshToken(httpServletRequest, "jkbbjsksbk");

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
        assertEquals(ErrorMessageConstants.REFRESH_TOKEN_MISSING_OR_NOT_VALID, response.getBody().getMessage());

    }


}