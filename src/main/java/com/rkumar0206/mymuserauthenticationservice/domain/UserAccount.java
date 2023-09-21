package com.rkumar0206.mymuserauthenticationservice.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDateTime;
import java.util.Date;

@Document(collection = "UserAccount")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserAccount {

    @Id
    private String id;

    @Field(name = "emailId")
    private String emailId;

    @Field(name = "password")
    private String password;

    @Field(name = "uid")
    private String uid;

    @Field(name = "name")
    private String name;

    @Field(name = "isAccountVerified")
    private boolean isAccountVerified;

    @Field(name = "resetPasswordToken")
    private String resetPasswordToken;

    private Date created;
    private Date modified;
}
