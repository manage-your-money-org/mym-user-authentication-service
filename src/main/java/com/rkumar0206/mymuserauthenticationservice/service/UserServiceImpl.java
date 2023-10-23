package com.rkumar0206.mymuserauthenticationservice.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.config.RoutingKeysConfig;
import com.rkumar0206.mymuserauthenticationservice.config.TokenConfig;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.EmailUpdateOTP;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.PasswordResetRabbitMQMessage;
import com.rkumar0206.mymuserauthenticationservice.model.request.PasswordResetRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserDetailsRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserEmailRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.repository.ConfirmationTokenRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.EmailUpdateOTPRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import com.rkumar0206.mymuserauthenticationservice.utlis.ModelMapper;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserAccountRepository userAccountRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailUpdateOTPRepository emailUpdateOTPRepository;
    private final RabbitTemplate rabbitTemplate;
    private final HttpServletRequest request;
    private final TokenConfig tokenConfig;
    private final RoutingKeysConfig routingKeysConfig;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserAccount userAccount = getUserByEmailId(username);

        if (userAccount == null) {
            throw new UsernameNotFoundException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
        } else if (!userAccount.isAccountVerified()) {

            try {
                sendConfirmationToken(userAccount.getEmailId());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            throw new UserException(ErrorMessageConstants.ACCOUNT_NOT_VERIFIED_ERROR);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        return new User(userAccount.getEmailId(), userAccount.getPassword(), authorities);
    }


    @Override
    public UserAccount getUserByEmailId(String emailId) {

        return userAccountRepository.findByEmailId(emailId).orElse(null);
    }

    @Override
    public UserAccount getUserByUid(String uid) {

        return userAccountRepository.findByUid(uid).orElse(null);
    }

    @Override
    public UserAccountResponse createUser(UserAccountRequest userAccountRequest) throws Exception {

        UserAccount newUserAccount;

        Optional<UserAccount> dbUserAccount = userAccountRepository.findByEmailId(
                userAccountRequest.getEmailId().trim()
        );

        if (dbUserAccount.isPresent() && !dbUserAccount.get().isAccountVerified()) {

            // if user is already present but is not verified then update the details and send a verification email
            newUserAccount = dbUserAccount.get();
        } else {

            // if no data is present with given emailId then it is a new user

            // checking for duplicates
            if (dbUserAccount.isPresent())
                throw new UserException(ErrorMessageConstants.DUPLICATE_EMAIL_ID_ERROR);

            newUserAccount = new UserAccount();

            newUserAccount.setUid(UUID.randomUUID().toString().replace("-", ""));
            newUserAccount.setEmailId(userAccountRequest.getEmailId().trim());
        }

        newUserAccount.setPassword(bCryptPasswordEncoder.encode(userAccountRequest.getPassword().trim()));
        newUserAccount.setName(userAccountRequest.getName().trim());
        newUserAccount.setAccountVerified(false);
        newUserAccount.setCreated(new Date(System.currentTimeMillis()));
        newUserAccount.setModified(new Date(System.currentTimeMillis()));
        userAccountRepository.save(newUserAccount);

        sendConfirmationToken(newUserAccount.getEmailId());

        return ModelMapper.buildUserAccountResponse(newUserAccount);
    }

    @Override
    public UserAccountResponse updateUserBasicDetails(UpdateUserDetailsRequest updateUserDetailsRequest) {

        UserAccount dbUserAccount = getAuthenticatedUserAccount();

        if (!dbUserAccount.getName().equals(updateUserDetailsRequest.getName())) {
            dbUserAccount.setName(updateUserDetailsRequest.getName());
        } else {
            return ModelMapper.buildUserAccountResponse(dbUserAccount);
        }

        return ModelMapper.buildUserAccountResponse(userAccountRepository.save(dbUserAccount));
    }

    @Override
    public void updateUserEmailId(UpdateUserEmailRequest updateUserEmailRequest) throws JsonProcessingException {

        UserAccount dbUserAccount = getAuthenticatedUserAccount();

        if (!dbUserAccount.getEmailId().equals(updateUserEmailRequest.getEmail())) {

            // check if new email id already exist
            Optional<UserAccount> userAccount = userAccountRepository.findByEmailId(updateUserEmailRequest.getEmail());

            if (userAccount.isPresent()) {
                throw new UserException(ErrorMessageConstants.DUPLICATE_EMAIL_ID_ERROR);
            }

            sendOTPToNewEmailId(dbUserAccount.getEmailId(), updateUserEmailRequest.getEmail());
        } else {
            throw new UserException(ErrorMessageConstants.NO_CHANGES_FOUND);
        }
    }


    @Override
    public AccountVerificationMessage verifyEmail(String token) {

        Optional<ConfirmationToken> confirmationToken = confirmationTokenRepository.findByConfirmationToken(token);

        if (confirmationToken.isPresent()) {

            Optional<UserAccount> user = userAccountRepository.findByEmailId(confirmationToken.get().getEmailId());

            if (user.isPresent()) {

                if (user.get().isAccountVerified()) {

                    return AccountVerificationMessage.ALREADY_VERIFIED;
                }

                user.get().setAccountVerified(true);
                userAccountRepository.save(user.get());
                confirmationTokenRepository.delete(confirmationToken.get());

                return AccountVerificationMessage.VERIFIED;
            } else {
                return AccountVerificationMessage.INVALID;
            }
        }
        return AccountVerificationMessage.INVALID;
    }

    @Override
    public UserAccount verifyOTPAndUpdateEmail(String otp) {

        UserAccount dbUserAccount = getAuthenticatedUserAccount();

        Optional<EmailUpdateOTP> emailUpdateOTP = emailUpdateOTPRepository.findByOldEmailId(dbUserAccount.getEmailId());

        if (emailUpdateOTP.isEmpty()) {
            throw new UserException(ErrorMessageConstants.NO_EMAIL_UPDATE_REQUEST_FOUND_FOR_THIS_USER);
        }

        if (emailUpdateOTP.get().getOtp().equals(otp.trim())) {

            // check if otp is expired or not
            try {
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(tokenConfig.getSecret().getBytes())).build();
                jwtVerifier.verify(emailUpdateOTP.get().getToken());
            } catch (JWTVerificationException e) {

                emailUpdateOTPRepository.delete(emailUpdateOTP.get());
                throw new UserException(ErrorMessageConstants.OTP_EXPIRED);
            }

            dbUserAccount.setEmailId(emailUpdateOTP.get().getNewEmailId());

            emailUpdateOTPRepository.delete(emailUpdateOTP.get());
            return userAccountRepository.save(dbUserAccount);

        } else {
            throw new UserException(ErrorMessageConstants.WRONG_OTP_SENT);
        }
    }

    @Override
    public void resetPassword(PasswordResetRequest passwordResetRequest) {

        UserAccount dbUserAccount = getAuthenticatedUserAccount();

        boolean isOldPasswordMatches = bCryptPasswordEncoder.matches(passwordResetRequest.getOldPassword(), dbUserAccount.getPassword());

        if (!isOldPasswordMatches) {
            throw new UserException(ErrorMessageConstants.OLD_PASSWORD_IS_INCORRECT);
        }

        dbUserAccount.setPassword(bCryptPasswordEncoder.encode(passwordResetRequest.getNewPassword().trim()));

        userAccountRepository.save(dbUserAccount);
    }

    /**
     * @param email
     * @param password
     * @detail This is used when user forgets his password. When user clicks on reset password url send to his email then this method will be used
     */
    @Override
    public void resetPassword(String email, String password) {

        UserAccount userAccount = getUserByEmailId(email.trim());

        userAccount.setPassword(bCryptPasswordEncoder.encode(password.trim()));
        userAccount.setResetPasswordToken(null);
        userAccountRepository.save(userAccount);
    }

    @Override
    public void sendPasswordResetUrlToEmailIdForForgotPassword(String email) throws JsonProcessingException {

        UserAccount userAccount = getUserByEmailId(email.trim());

        if (userAccount == null) {
            throw new UserException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
        }

        String token = generateTokenWithExpiryInMinutes(email.trim(), 10);

        userAccount.setResetPasswordToken(token);
        userAccountRepository.save(userAccount);

        PasswordResetRabbitMQMessage passwordResetRabbitMQMessage = new PasswordResetRabbitMQMessage(
                email.trim(), token
        );

        publishMessage(routingKeysConfig.getPasswordReset(), new ObjectMapper().writeValueAsBytes(passwordResetRabbitMQMessage));
    }

    @Override
    public void checkResetPasswordToken(String email, String token) {

        UserAccount userAccount = getUserByEmailId(email.trim());

        if (MymUtil.isNotValid(userAccount.getResetPasswordToken())) {
            throw new UserException(ErrorMessageConstants.NO_PASSWORD_RESET_REQUEST_FOUND_FOR_THIS_USER);
        }

        if (!userAccount.getResetPasswordToken().equals(token.trim())) {
            throw new UserException(ErrorMessageConstants.TOKEN_NOT_VALID_FOR_PASSWORD_RESET);
        }
    }

    private UserAccount getAuthenticatedUserAccount() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return getUserByEmailId(authentication.getPrincipal().toString());

    }

    private void sendConfirmationToken(String emailId) throws Exception {

        ConfirmationToken confirmationToken;
        Optional<ConfirmationToken> confirmationTokenDB = confirmationTokenRepository.findByEmailId(emailId);

        if (confirmationTokenDB.isEmpty()) {

            confirmationToken = new ConfirmationToken();
            confirmationToken.setEmailId(emailId);
        } else {

            confirmationToken = confirmationTokenDB.get();
        }

        confirmationToken.setConfirmationToken(UUID.randomUUID().toString());
        confirmationToken.setCreatedDate(System.currentTimeMillis());
        confirmationTokenRepository.save(confirmationToken);

        publishMessage(routingKeysConfig.getAccountVerification(), new ObjectMapper().writeValueAsBytes(confirmationToken));
    }

    private void sendOTPToNewEmailId(String oldEmailAddress, String newEmailAddress) throws JsonProcessingException {

        EmailUpdateOTP emailUpdateOTP;
        Optional<EmailUpdateOTP> emailUpdateOTPDb = emailUpdateOTPRepository.findByOldEmailId(
                oldEmailAddress
        );

        emailUpdateOTP = emailUpdateOTPDb.orElseGet(EmailUpdateOTP::new);

        emailUpdateOTP.setOldEmailId(oldEmailAddress);
        emailUpdateOTP.setNewEmailId(newEmailAddress);
        emailUpdateOTP.setOtp(MymUtil.generateOTP());


        String token = generateTokenWithExpiryInMinutes(emailUpdateOTP.getOldEmailId(), 10);

        emailUpdateOTP.setToken(token);

        emailUpdateOTPRepository.save(emailUpdateOTP);

        publishMessage(routingKeysConfig.getEmailUpdateOtp(), new ObjectMapper().writeValueAsBytes(emailUpdateOTP));
    }

    private String generateTokenWithExpiryInMinutes(String emailId, int expireIn) {
        return JWT.create()
                .withSubject(emailId)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expireIn)))
                .withIssuer(tokenConfig.getIssuer())
                .sign(Algorithm.HMAC256(tokenConfig.getSecret().getBytes()));
    }

    private void publishMessage(String routingKey, byte[] body) {

        // Publishing message to rabbitMQ -> (consumer: mym-email-notification-service)
        MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReceivedRoutingKey(routingKey);
        messageProperties.getHeaders().put(Constants.CORRELATION_ID, request.getHeader(Constants.CORRELATION_ID));

        rabbitTemplate.send(
                "MYM",
                routingKey,
                new Message(body, messageProperties)
        );
    }
}
