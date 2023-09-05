package com.rkumar0206.mymuserauthenticationservice.constantsAndEnums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AccountVerificationMessage {
    VERIFIED("Account verified."),
    ALREADY_VERIFIED("Account already verified. Please login."),
    INVALID("Invalid token.");

    private final String value;
}
