package com.rkumar0206.mymuserauthenticationservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.repository.ConfirmationTokenRepository;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserDetailsService, UserService {

    private final UserAccountRepository userAccountRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserAccount userAccount = getUserByEmailId(username);

        if (userAccount == null) {
            throw new UsernameNotFoundException(ErrorMessageConstants.USER_NOT_FOUND_ERROR);
        } else if (!userAccount.isAccountVerified()) {

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

        // init confirmation token
        ConfirmationToken confirmationToken = new ConfirmationToken();
        confirmationToken.setConfirmationToken(UUID.randomUUID().toString());
        confirmationToken.setEmailId(newUserAccount.getEmailId());
        confirmationToken.setCreatedDate(System.currentTimeMillis());

        confirmationTokenRepository.save(confirmationToken);

        emailService.sendConfirmationToken(confirmationToken);

        return objectMapper.convertValue(newUserAccount, UserAccountResponse.class);
    }
}
