package com.rkumar0206.mymuserauthenticationservice.constantsAndEnums;

public class ErrorMessageConstants {

    public static final String USER_NOT_FOUND_ERROR = "User not found";
    public static final String ACCOUNT_NOT_VERIFIED_ERROR = "Account not verified! A verification mail has been sent to your email, please verify";

    public static final String DUPLICATE_EMAIL_ID_ERROR = "This email-id is already in use";
    public static final String INVALID_USER_DETAILS_ERROR = "User details invalid!!. name, email-id, and password fields are mandatory";
    public static final String INVALID_USER_DETAILS_FOR_UPDATE_ERROR = "User details invalid!!. name is mandatory";
    public static final String PERMISSION_DENIED = "Permission denied";
    public static final String REFRESH_TOKEN_MISSING_OR_NOT_VALID = "Refresh token is missing or not valid";
    public static final String NO_CHANGES_FOUND = "No changes found for updating";
    public static final String OTP_NOT_VALID = "OTP not valid";
    public static final String NO_EMAIL_UPDATE_REQUEST_FOUND_FOR_THIS_USER = "No email update request found for this user";
    public static final String WRONG_OTP_SENT = "OTP not correct";
    public static final String OTP_EXPIRED = "This OTP is expired. Please send new request";
}
