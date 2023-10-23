package com.rkumar0206.mymuserauthenticationservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rkumar0206.mymuserauthenticationservice.config.RoutingKeysConfig;
import com.rkumar0206.mymuserauthenticationservice.config.TokenConfig;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.controllers.JWT_UtilTestHelper;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.EmailUpdateOTP;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.PasswordResetRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserDetailsRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserEmailRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.repository.ConfirmationTokenRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.EmailUpdateOTPRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserAccountRepository userAccountRepository;
    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Mock
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Mock
    private EmailUpdateOTPRepository emailUpdateOTPRepository;
    @Mock
    private RabbitTemplate rabbitTemplate;
    @Mock
    private HttpServletRequest request;
    @Mock
    private TokenConfig tokenConfig;
    @Mock
    private RoutingKeysConfig routingKeysConfig;
    @InjectMocks
    private UserServiceImpl userService;
    private UserAccount userAccount;

    @BeforeEach
    void setup() {

        userAccount = new UserAccount(
                "sdbchbsjhbsjbsjh",
                "test@gmail.com",
                "jbsdjhsjhvsvghsvghsvvsghvsgvsvhsvhsv",
                "skjbhsbbsjhbshbhsbs",
                "Rohit Kumar",
                true,
                "shjgshjgshjgsghjsgj",
                new Date(),
                new Date()

        );
    }

    @Test
    void loadUserByUsername_Success() {


        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        UserDetails userDetails = userService.loadUserByUsername(userAccount.getEmailId());

        assertEquals(userDetails.getUsername(), userAccount.getEmailId());
    }

    @Test
    void loadUserByUsername_user_not_present_exception_thrown() {


        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.loadUserByUsername(userAccount.getEmailId()))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
    }

    @Test
    void loadUserByUsername_user_not_verified_exception_thrown() {

        userAccount.setAccountVerified(false);
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        assertThatThrownBy(() -> userService.loadUserByUsername(userAccount.getEmailId()))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR);
    }


    @Test
    void getUserByEmailId_userFound() {

        when(userAccountRepository.findByEmailId(userAccount.getEmailId())).thenReturn(Optional.of(userAccount));

        assertNotNull(userService.getUserByEmailId(userAccount.getEmailId()));

    }

    @Test
    void getUserByEmailId_userNotFound() {

        when(userAccountRepository.findByEmailId(userAccount.getEmailId())).thenReturn(Optional.empty());

        assertNull(userService.getUserByEmailId(userAccount.getEmailId()));

    }


    @Test
    void getUserByUid_userFound() {

        when(userAccountRepository.findByUid(userAccount.getUid())).thenReturn(Optional.of(userAccount));

        assertNotNull(userService.getUserByUid(userAccount.getUid()));

    }

    @Test
    void getUserByUid_userNotFound() {

        when(userAccountRepository.findByUid(userAccount.getUid())).thenReturn(Optional.empty());

        assertNull(userService.getUserByUid(userAccount.getUid()));
    }


    @Test
    void createUser_newUser_Success() throws Exception {

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.empty());
        when(confirmationTokenRepository.findByEmailId(anyString())).thenReturn(Optional.empty());

        UserAccountRequest userAccountRequest = UserAccountRequest.builder()
                .emailId(userAccount.getEmailId())
                .password("testPass")
                .name("Rohit Kumar")
                .build();

        userService.createUser(userAccountRequest);

        ArgumentCaptor<UserAccount> userAccountResponseArgumentCaptor =
                ArgumentCaptor.forClass(UserAccount.class);

        ArgumentCaptor<ConfirmationToken> confirmationTokenArgumentCaptor =
                ArgumentCaptor.forClass(ConfirmationToken.class);

        verify(userAccountRepository).save(userAccountResponseArgumentCaptor.capture());
        verify(confirmationTokenRepository).save(confirmationTokenArgumentCaptor.capture());
        //verify(emailService, times(1)).sendConfirmationToken(any());

        UserAccount user = userAccountResponseArgumentCaptor.getValue();
        ConfirmationToken confirmationToken = confirmationTokenArgumentCaptor.getValue();

        assertEquals(userAccountRequest.getName(), user.getName());
        assertEquals(userAccountRequest.getEmailId(), user.getEmailId());
        assertNotEquals(userAccountRequest.getPassword(), user.getPassword()); // password should be encrypted
        assertFalse(user.isAccountVerified());

        assertEquals(confirmationToken.getEmailId(), user.getEmailId());
        assertNotNull(confirmationToken.getConfirmationToken());
    }

    @Test
    void createUser_userIsPresent_but_not_verified_Success() throws Exception {

        userAccount.setAccountVerified(false);

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));
        when(confirmationTokenRepository.findByEmailId(anyString())).thenReturn(Optional.empty());

        UserAccountRequest userAccountRequest = UserAccountRequest.builder()
                .emailId(userAccount.getEmailId())
                .password("testPass")
                .name("Rohit Kumar")
                .build();

        userService.createUser(userAccountRequest);

        ArgumentCaptor<UserAccount> userAccountResponseArgumentCaptor =
                ArgumentCaptor.forClass(UserAccount.class);

        ArgumentCaptor<ConfirmationToken> confirmationTokenArgumentCaptor =
                ArgumentCaptor.forClass(ConfirmationToken.class);

        verify(userAccountRepository).save(userAccountResponseArgumentCaptor.capture());
        verify(confirmationTokenRepository).save(confirmationTokenArgumentCaptor.capture());
        //verify(emailService, times(1)).sendConfirmationToken(any());

        UserAccount user = userAccountResponseArgumentCaptor.getValue();
        ConfirmationToken confirmationToken = confirmationTokenArgumentCaptor.getValue();

        assertEquals(userAccountRequest.getName(), user.getName());
        assertEquals(userAccountRequest.getEmailId(), user.getEmailId());
        assertNotEquals(userAccountRequest.getPassword(), user.getPassword()); // password should be encrypted
        assertFalse(user.isAccountVerified());

        assertEquals(confirmationToken.getEmailId(), user.getEmailId());
        assertNotNull(confirmationToken.getConfirmationToken());
    }

    @Test
    void createUser_userAlreadyPresentWithGivenEmailId_exception_thrown() {


        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        UserAccountRequest userAccountRequest = UserAccountRequest.builder()
                .emailId(userAccount.getEmailId())
                .password("testPass")
                .name("Rohit Kumar")
                .build();

        assertThatThrownBy(() -> userService.createUser(userAccountRequest))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.DUPLICATE_EMAIL_ID_ERROR);
    }


    @Test
    void verifyEmail_Success() {

        userAccount.setAccountVerified(false);

        ConfirmationToken confirmationToken = new ConfirmationToken(
                "sbjhsbj", userAccount.getEmailId(), UUID.randomUUID().toString(), System.currentTimeMillis()
        );

        when(confirmationTokenRepository.findByConfirmationToken(anyString())).thenReturn(Optional.of(confirmationToken));
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));
        doNothing().when(confirmationTokenRepository).delete(any());

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(
                confirmationToken.getConfirmationToken()
        );

        ArgumentCaptor<UserAccount> userAccountArgumentCaptor = ArgumentCaptor.forClass(UserAccount.class);

        verify(userAccountRepository).save(userAccountArgumentCaptor.capture());
        verify(confirmationTokenRepository, times(1)).delete(any());

        assertEquals(AccountVerificationMessage.VERIFIED, accountVerificationMessage);
        assertTrue(userAccountArgumentCaptor.getValue().isAccountVerified());
    }

    @Test
    void verifyEmail_already_verified_Success() {

        userAccount.setAccountVerified(true);

        ConfirmationToken confirmationToken = new ConfirmationToken(
                "sbjhsbj", userAccount.getEmailId(), UUID.randomUUID().toString(), System.currentTimeMillis()
        );

        when(confirmationTokenRepository.findByConfirmationToken(anyString())).thenReturn(Optional.of(confirmationToken));
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(
                confirmationToken.getConfirmationToken()
        );

        assertEquals(AccountVerificationMessage.ALREADY_VERIFIED, accountVerificationMessage);
    }

    @Test
    void verifyEmail_userNotFound_Invalid() {

        ConfirmationToken confirmationToken = new ConfirmationToken(
                "sbjhsbj", userAccount.getEmailId(), UUID.randomUUID().toString(), System.currentTimeMillis()
        );

        when(confirmationTokenRepository.findByConfirmationToken(anyString())).thenReturn(Optional.of(confirmationToken));
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.empty());

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(
                confirmationToken.getConfirmationToken()
        );

        assertEquals(AccountVerificationMessage.INVALID, accountVerificationMessage);
    }

    @Test
    void verifyEmail_confirmationTokenNotFound_Invalid() {

        ConfirmationToken confirmationToken = new ConfirmationToken(
                "sbjhsbj", userAccount.getEmailId(), UUID.randomUUID().toString(), System.currentTimeMillis()
        );

        when(confirmationTokenRepository.findByConfirmationToken(anyString())).thenReturn(Optional.empty());

        AccountVerificationMessage accountVerificationMessage = userService.verifyEmail(
                confirmationToken.getConfirmationToken()
        );

        assertEquals(AccountVerificationMessage.INVALID, accountVerificationMessage);
    }

    @Test
    void updateUserBasicDetails_Success() {

        mockSecurityContextAndAuthentication();

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        //******For Model Mapper*****
        when(userAccountRepository.save(any())).thenReturn(userAccount);
        //****************************

        UpdateUserDetailsRequest updateUserDetailsRequest = new UpdateUserDetailsRequest(
                "Test name 2"
        );

        userService.updateUserBasicDetails(updateUserDetailsRequest);

        ArgumentCaptor<UserAccount> argumentCaptor = ArgumentCaptor.forClass(UserAccount.class);
        verify(userAccountRepository).save(argumentCaptor.capture());

        assertEquals(updateUserDetailsRequest.getName(), argumentCaptor.getValue().getName());

    }

    @Test
    void updateUserBasicDetails_whenNothingChanged_Success() {

        mockSecurityContextAndAuthentication();

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        UpdateUserDetailsRequest updateUserDetailsRequest = new UpdateUserDetailsRequest(
                userAccount.getName()
        );

        userService.updateUserBasicDetails(updateUserDetailsRequest);

        ArgumentCaptor<UserAccount> argumentCaptor = ArgumentCaptor.forClass(UserAccount.class);
        verify(userAccountRepository, times(0)).save(argumentCaptor.capture());
    }


    @Test
    void updateUserEmailId_Success() throws JsonProcessingException {

        mockSecurityContextAndAuthentication();

        when(userAccountRepository.findByEmailId(userAccount.getEmailId())).thenReturn(Optional.of(userAccount));

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                "mttestemail@gmail.com"
        );

        when(userAccountRepository.findByEmailId(updateUserEmailRequest.getEmail()))
                .thenReturn(Optional.empty());

        when(emailUpdateOTPRepository.findByOldEmailId(anyString())).thenReturn(Optional.empty());

        when(tokenConfig.getIssuer()).thenReturn("sdjbsbkjsb");
        when(tokenConfig.getSecret()).thenReturn("sknskbskbksbkjsb");

        userService.updateUserEmailId(updateUserEmailRequest);

        ArgumentCaptor<EmailUpdateOTP> argumentCaptor = ArgumentCaptor.forClass(EmailUpdateOTP.class);
        verify(emailUpdateOTPRepository).save(argumentCaptor.capture());

        assertEquals(updateUserEmailRequest.getEmail(), argumentCaptor.getValue().getNewEmailId());
    }


    @Test
    void updateUserEmailId_EmailIdAlreadyExist_ExceptionThrown() throws JsonProcessingException {

        mockSecurityContextAndAuthentication();

        when(userAccountRepository.findByEmailId(userAccount.getEmailId())).thenReturn(Optional.of(userAccount));

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                "mttestemail@gmail.com"
        );

        when(userAccountRepository.findByEmailId(updateUserEmailRequest.getEmail()))
                .thenReturn(Optional.of(UserAccount.builder()
                        .emailId(updateUserEmailRequest.getEmail())
                        .build()));

        assertThatThrownBy(() -> userService.updateUserEmailId(updateUserEmailRequest))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.DUPLICATE_EMAIL_ID_ERROR);
    }

    @Test
    void updateUserEmailId_SameEmailSent_ExceptionThrown() throws JsonProcessingException {

        mockSecurityContextAndAuthentication();

        when(userAccountRepository.findByEmailId(userAccount.getEmailId())).thenReturn(Optional.of(userAccount));

        UpdateUserEmailRequest updateUserEmailRequest = new UpdateUserEmailRequest(
                userAccount.getEmailId()
        );


        assertThatThrownBy(() -> userService.updateUserEmailId(updateUserEmailRequest))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.NO_CHANGES_FOUND);
    }


    @Test
    void verifyOTPAndUpdateEmail_Success() {

        mockSecurityContextAndAuthentication();

        EmailUpdateOTP emailUpdateOTP = EmailUpdateOTP.builder()
                .id("jknsknkjnkjsnk")
                .otp("435675")
                .newEmailId("testemail2@test.com")
                .oldEmailId("testemail@test.com")
                .token(new JWT_UtilTestHelper().createEmailOtpToken())
                .build();

        userAccount.setEmailId(emailUpdateOTP.getOldEmailId());
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        when(emailUpdateOTPRepository.findByOldEmailId(anyString()))
                .thenReturn(Optional.of(emailUpdateOTP));

        when(tokenConfig.getSecret()).thenReturn("secret"); // same as in JWT_UtilTestHelper

        userService.verifyOTPAndUpdateEmail(emailUpdateOTP.getOtp());


        verify(emailUpdateOTPRepository, times(1)).delete(any());

        ArgumentCaptor<UserAccount> userAccountArgumentCaptor = ArgumentCaptor.forClass(UserAccount.class);
        verify(userAccountRepository).save(userAccountArgumentCaptor.capture());

        assertEquals(emailUpdateOTP.getNewEmailId(), userAccountArgumentCaptor.getValue().getEmailId());

    }

    @Test
    void verifyOTPAndUpdateEmail_OTPNotMatch_ExceptionThrown() {

        mockSecurityContextAndAuthentication();

        EmailUpdateOTP emailUpdateOTP = EmailUpdateOTP.builder()
                .id("jknsknkjnkjsnk")
                .otp("435675")
                .newEmailId("testemail2@test.com")
                .oldEmailId("testemail@test.com")
                .token(new JWT_UtilTestHelper().createEmailOtpToken())
                .build();

        userAccount.setEmailId(emailUpdateOTP.getOldEmailId());
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        when(emailUpdateOTPRepository.findByOldEmailId(anyString()))
                .thenReturn(Optional.of(emailUpdateOTP));

        assertThatThrownBy(() -> userService.verifyOTPAndUpdateEmail("976655"))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.WRONG_OTP_SENT);

    }


    private void mockSecurityContextAndAuthentication() {
        Authentication authentication = new UsernamePasswordAuthenticationToken("test@gmail.com", null);
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);

        Mockito.when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void resetPasswordUserAuthenticated_Success() {

        mockSecurityContextAndAuthentication();
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));
        when(bCryptPasswordEncoder.matches(anyString(), anyString())).thenReturn(true);

        String oldPassword = userAccount.getPassword();

        PasswordResetRequest passwordResetRequest = new PasswordResetRequest(
                oldPassword, "rohitkumar"
        );

        userService.resetPassword(passwordResetRequest);

        ArgumentCaptor<UserAccount> userAccountArgumentCaptor = ArgumentCaptor.forClass(UserAccount.class);

        verify(userAccountRepository, times(1)).save(userAccountArgumentCaptor.capture());

        assertNotEquals(oldPassword, userAccountArgumentCaptor.getValue().getPassword());
    }

    @Test
    void resetPasswordUserAuthenticated_OldPasswordDoesNotMatch_ExceptionThrown() {

        mockSecurityContextAndAuthentication();
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));
        when(bCryptPasswordEncoder.matches(anyString(), anyString())).thenReturn(false);

        PasswordResetRequest passwordResetRequest = new PasswordResetRequest(
                userAccount.getPassword(), "rohitkumar"
        );
        assertThatThrownBy(() -> userService.resetPassword(passwordResetRequest))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.OLD_PASSWORD_IS_INCORRECT);
    }


    @Test
    void resetPasswordUser_UnAuthenticated_Success() {

        String oldPassword = userAccount.getPassword();
        userAccount.setResetPasswordToken("sdcbjhsbcsbjhbjsbshjbshjbsjsvsgvsjh");
        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        userService.resetPassword(userAccount.getEmailId(), "rohitkumar");

        ArgumentCaptor<UserAccount> userAccountArgumentCaptor = ArgumentCaptor.forClass(UserAccount.class);

        verify(userAccountRepository, times(1)).save(userAccountArgumentCaptor.capture());

        assertNotEquals(oldPassword, userAccountArgumentCaptor.getValue().getPassword());
        assertNull(userAccountArgumentCaptor.getValue().getResetPasswordToken());
    }


    @Test
    void sendPasswordResetUrlToEmailIdForForgotPassword_Success() throws JsonProcessingException {

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));
        when(tokenConfig.getSecret()).thenReturn("secret");

        userService.sendPasswordResetUrlToEmailIdForForgotPassword(userAccount.getEmailId());

        ArgumentCaptor<UserAccount> userAccountArgumentCaptor = ArgumentCaptor.forClass(UserAccount.class);

        verify(userAccountRepository, times(1)).save(userAccountArgumentCaptor.capture());

        assertNotNull(userAccountArgumentCaptor.getValue().getResetPasswordToken());
    }

    @Test
    void sendPasswordResetUrlToEmailIdForForgotPassword_UserNotFound_ExceptionThrown() throws JsonProcessingException {

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.empty());


        assertThatThrownBy(() -> userService.sendPasswordResetUrlToEmailIdForForgotPassword(userAccount.getEmailId()))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
    }


    @Test
    void checkResetPasswordToken_ResetPasswordTokenNotValid_ExceptionThrown() {

        userAccount.setResetPasswordToken(null);

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));

        assertThatThrownBy(() -> userService.checkResetPasswordToken(userAccount.getEmailId(), "token"))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.NO_PASSWORD_RESET_REQUEST_FOUND_FOR_THIS_USER);

    }

    @Test
    void checkResetPasswordToken_ResetPasswordTokenAndTokenReceivedIsNotSame_ExceptionThrown() {

        userAccount.setResetPasswordToken("resetpasswordtoken");

        when(userAccountRepository.findByEmailId(anyString())).thenReturn(Optional.of(userAccount));


        assertThatThrownBy(() -> userService.checkResetPasswordToken(userAccount.getEmailId(), "notequaltoresettoken"))
                .isInstanceOf(UserException.class)
                .hasMessage(ErrorMessageConstants.TOKEN_NOT_VALID_FOR_PASSWORD_RESET);

    }

}