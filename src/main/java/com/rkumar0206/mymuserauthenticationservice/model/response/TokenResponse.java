package com.rkumar0206.mymuserauthenticationservice.model.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class TokenResponse {

    private String access_token;
    private String refresh_token;
}
