package com.rkumar0206.mymuserauthenticationservice.domain;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "EmailUpdateOTP")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmailUpdateOTP {

    @Id
    private String id;

    private String oldEmailId;
    private String newEmailId;
    private String otp;
    private String token;
}
