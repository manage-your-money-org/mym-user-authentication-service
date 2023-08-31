package com.rkumar0206.mymuserauthenticationservice.model.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserAccountResponse {

    private String name;
    private String emailId;
    private String uid;
    private boolean isAccountVerified;
}
