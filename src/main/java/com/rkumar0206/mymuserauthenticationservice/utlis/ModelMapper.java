package com.rkumar0206.mymuserauthenticationservice.utlis;

import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;

import java.time.LocalDateTime;

public class ModelMapper {

    public static UserAccountResponse buildUserAccountResponse(UserAccount userAccount) {

        return UserAccountResponse.builder()
                .isAccountVerified(userAccount.isAccountVerified())
                .name(userAccount.getName())
                .emailId(userAccount.getEmailId())
                .uid(userAccount.getUid())
                .created(userAccount.getCreated())
                .modified(userAccount.getModified())
                .build();
    }

}
