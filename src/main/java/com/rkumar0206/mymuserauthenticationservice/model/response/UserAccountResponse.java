package com.rkumar0206.mymuserauthenticationservice.model.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserAccountResponse {

    private String name;
    private String emailId;
    private String uid;
    private boolean isAccountVerified;
}
