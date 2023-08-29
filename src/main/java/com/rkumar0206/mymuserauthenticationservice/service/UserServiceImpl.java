package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.exceptions.UserException;
import com.rkumar0206.mymuserauthenticationservice.repository.UserAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserServiceImpl implements UserDetailsService, UserService {

    @Autowired
    private UserAccountRepository userAccountRepository;

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
}
