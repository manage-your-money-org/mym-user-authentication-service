package com.rkumar0206.mymuserauthenticationservice.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDateTime;
import java.util.Date;

@Document(collection = "ConfirmationToken")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ConfirmationToken {

    @Id
    private String id;

    @Field(name = "emailId")
    private String emailId;

    @Field(name = "confirmationToken")
    private String confirmationToken;

    @Field(name = "createdDate")
    private long createdDate;
}
