package com.rkumar0206.mymuserauthenticationservice.utlis;

public class MymStringUtil {

    public static boolean isValid(String str) {

        return str != null && !str.trim().isEmpty();
    }
}
