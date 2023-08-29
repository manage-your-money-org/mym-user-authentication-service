package com.rkumar0206.mymuserauthenticationservice.utlis;

import java.util.ArrayList;
import java.util.List;

public class Utility {

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
}
