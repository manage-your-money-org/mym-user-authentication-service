package com.rkumar0206.mymuserauthenticationservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.AccountVerificationMessage;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserDetailsRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UpdateUserEmailRequest;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {

    UserAccount getUserByEmailId(String emailId);

    UserAccount getUserByUid(String uid);

    UserAccountResponse createUser(UserAccountRequest userAccountRequest) throws Exception;

    UserAccountResponse updateUserBasicDetails(UpdateUserDetailsRequest updateUserDetailsRequest);

    void updateUserEmailId(UpdateUserEmailRequest updateUserEmailRequest) throws JsonProcessingException;

    AccountVerificationMessage verifyEmail(String token);

    UserAccount verifyOTPAndUpdateEmail(String otp);
}
