package com.rkumar0206.mymuserauthenticationservice.model.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymUtil;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
public class UserAccountRequest {

    private String name;
    private String emailId;
    private String password;

    @JsonIgnore
    public boolean isValid() {

        return MymUtil.isValid(name)
                && MymUtil.isValid(emailId)
                && MymUtil.isEmailStringValid(emailId)
                && MymUtil.isValid(password);
    }
}
