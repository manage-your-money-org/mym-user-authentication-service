package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.repository.ConfirmationTokenRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
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
    private EmailService emailService;
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

        userService = new UserServiceImpl(userAccountRepository, bCryptPasswordEncoder, confirmationTokenRepository, emailService);
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
        verify(emailService, times(1)).sendConfirmationToken(any());

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
        verify(emailService, times(1)).sendConfirmationToken(any());

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

}