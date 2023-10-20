package com.rkumar0206.mymuserauthenticationservice.utlis;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Slf4j
public class MymUtil {

    public static List<String> getServletPathsForWhichNoAuthenticationIsRequired() {

        List<String> paths = new ArrayList<>();

        paths.add("/mym/app/users/login");
        paths.add("/mym/api/users/create");
        paths.add("/mym/api/users/account/verify");
        paths.add("/mym/api/users/token/refresh");
        paths.add("/mym/api/users/account/forgotPassword");
        paths.add("/mym/api/users/account/passwordReset");

        return paths;
    }

    public static String getTokenFromAuthorizationHeader(String authorizationHeader) {

        return authorizationHeader.substring(Constants.BEARER.length());
    }

    public static boolean isValid(String str) {

        return str != null && !str.trim().isEmpty();
    }

    public static boolean isNotValid(String str) {

        return !isValid(str);
    }

    public static void setAppropriateResponseStatus(CustomResponse response, Exception ex, String correlationId) {

        log.error(createLog(correlationId, ex.getMessage()));

        switch (ex.getMessage()) {

            case ErrorMessageConstants.PERMISSION_DENIED -> response.setStatus(HttpStatus.FORBIDDEN.value());

            case ErrorMessageConstants.INVALID_USER_DETAILS_ERROR, ErrorMessageConstants.INVALID_USER_DETAILS_FOR_UPDATE_ERROR, ErrorMessageConstants.DUPLICATE_EMAIL_ID_ERROR,
                    ErrorMessageConstants.NO_CHANGES_FOUND, ErrorMessageConstants.NO_EMAIL_UPDATE_REQUEST_FOUND_FOR_THIS_USER, ErrorMessageConstants.OTP_NOT_VALID,
                    ErrorMessageConstants.WRONG_OTP_SENT, ErrorMessageConstants.OTP_EXPIRED ->
                    response.setStatus(HttpStatus.BAD_REQUEST.value());

            case ErrorMessageConstants.USER_NOT_FOUND_ERROR -> response.setStatus(HttpStatus.NO_CONTENT.value());

            default -> response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        response.setMessage(String.format(Constants.FAILED_, ex.getMessage()));
    }

    public static boolean isEmailStringValid(String email) {

        String regex = "^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$";
        return email.matches(regex);
    }

    public static String generateOTP() {

        int min = 100000;
        int max = 999999;

        Random random = new Random();

        int otpValue = random.nextInt(max - min + 1) + min;

        return String.format("%06d", otpValue);
    }

    public static String createLog(String correlationId, String message) {

        return String.format(Constants.LOG_MESSAGE_STRUCTURE, correlationId, message);
    }

}
