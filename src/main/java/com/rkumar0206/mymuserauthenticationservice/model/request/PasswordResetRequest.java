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
public class PasswordResetRequest {

    private String oldPassword;
    private String newPassword;

    @JsonIgnore
    public boolean isValid() {

        return MymUtil.isValid(this.oldPassword)
                && MymUtil.isValid(this.newPassword)
                && !(this.oldPassword.equals(this.newPassword));
    }
}
