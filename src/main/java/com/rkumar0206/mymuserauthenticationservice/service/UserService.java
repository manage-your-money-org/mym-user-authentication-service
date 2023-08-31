package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;

public interface UserService {

    UserAccount getUserByEmailId(String emailId);

    UserAccountResponse createUser(UserAccountRequest userAccountRequest) throws Exception;
}
