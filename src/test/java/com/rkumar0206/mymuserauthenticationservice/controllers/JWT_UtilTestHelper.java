package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class JWT_UtilTestHelper {


    public String generateAccessToken(UserAccount userAccount) {

        long expiry = System.currentTimeMillis() + (Constants.ONE_DAY_MILLISECONDS);

        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("name", userAccount.getName());

        return JWT.create()
                .withSubject(userAccount.getEmailId())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withKeyId(UUID.randomUUID().toString())
                .withExpiresAt(new Date(expiry))
                .withClaim("uid", userAccount.getUid())
                .withClaim("name", userAccount.getName())
                .withClaim("isAccountVerified", userAccount.isAccountVerified())
                .withIssuer("issuer")
                .sign(Algorithm.HMAC256("secret"));
    }

    public String generateRefreshToken(UserAccount userAccount) {

        long expiry = System.currentTimeMillis() + (Constants.ONE_DAY_MILLISECONDS);

        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("name", userAccount.getName());

        return JWT.create()
                .withSubject(userAccount.getEmailId())
                .withExpiresAt(new Date(expiry))
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withIssuer("issuer")
                .withClaim("uid", userAccount.getUid())
                .withClaim(Constants.TOKEN_TYPE, Constants.REFRESH_TOKEN)
                .sign(Algorithm.HMAC256("secret"));
    }

    public DecodedJWT isTokenValid(String token) throws JWTVerificationException {

        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("secret")).build();
        return jwtVerifier.verify(token);
    }
}
