package com.rkumar0206.mymuserauthenticationservice.utlis;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;

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

    public static void setAppropriateResponseStatus(CustomResponse response, Exception ex) {

        switch (ex.getMessage()) {

            case ErrorMessageConstants.PERMISSION_DENIED -> response.setStatus(HttpStatus.FORBIDDEN.value());

            case ErrorMessageConstants.INVALID_USER_DETAILS_ERROR -> response.setStatus(HttpStatus.BAD_REQUEST.value());

            case ErrorMessageConstants.USER_NOT_FOUND_ERROR -> response.setStatus(HttpStatus.NO_CONTENT.value());

            default -> response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }


        response.setMessage(String.format(Constants.FAILED_, ex.getMessage()));
    }
}
