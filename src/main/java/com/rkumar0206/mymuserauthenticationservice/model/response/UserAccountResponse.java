package com.rkumar0206.mymuserauthenticationservice.model.response;

import lombok.*;

import java.util.Date;

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
    private Date created;
    private Date modified;
}
