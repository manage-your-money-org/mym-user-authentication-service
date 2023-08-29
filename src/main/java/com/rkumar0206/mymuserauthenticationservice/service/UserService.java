package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;

public interface UserService {

    public UserAccount getUserByEmailId(String emailId);
}
