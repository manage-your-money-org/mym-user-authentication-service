package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.repository.ConfirmationTokenRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import com.rkumar0206.mymuserauthenticationservice.utlis.ModelMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserAccountRepository userAccountRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailService emailService;
    //private final ObjectMapper objectMapper;

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
        userAccountRepository.save(newUserAccount);

        sendConfirmationToken(newUserAccount.getEmailId());

        return ModelMapper.buildUserAccountResponse(newUserAccount);
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

        emailService.sendConfirmationToken(confirmationToken);
    }
}
