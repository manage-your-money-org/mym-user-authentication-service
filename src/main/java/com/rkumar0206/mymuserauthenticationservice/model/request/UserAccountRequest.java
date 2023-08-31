package com.rkumar0206.mymuserauthenticationservice.model.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.util.StringUtils;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserAccountRequest {

    private String name;
    private String emailId;
    private String password;

    @JsonIgnore
    public boolean isValid() {

        return StringUtils.hasLength(name.trim())
                && StringUtils.hasLength(emailId.trim())
                && StringUtils.hasLength(password.trim());
    }
}
