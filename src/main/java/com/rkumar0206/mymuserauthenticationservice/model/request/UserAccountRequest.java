package com.rkumar0206.mymuserauthenticationservice.model.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.rkumar0206.mymuserauthenticationservice.utlis.MymStringUtil;
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

        return MymStringUtil.isValid(name)
                && MymStringUtil.isValid(emailId)
                && MymStringUtil.isValid(password);
    }
}
