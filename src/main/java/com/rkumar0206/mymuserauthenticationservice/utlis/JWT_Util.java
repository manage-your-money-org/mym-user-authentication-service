package com.rkumar0206.mymuserauthenticationservice.utlis;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rkumar0206.mymuserauthenticationservice.config.TokenConfig;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JWT_Util {

    private final TokenConfig tokenConfig;
    private final UserService userService;
    private Algorithm algorithm;

    @Autowired
    public JWT_Util(UserService userService, TokenConfig tokenConfig) {

        this.tokenConfig = tokenConfig;

        if (tokenConfig.getSecret() != null) {
            algorithm = Algorithm.HMAC256(tokenConfig.getSecret().getBytes());
        }

        this.userService = userService;
    }

    public String generateAccessToken(User user) {

        UserAccount userAccount = userService.getUserByEmailId(user.getUsername());
        return generateAccessToken(userAccount);
    }

    public String generateAccessToken(UserAccount userAccount) {

        long expiry = System.currentTimeMillis() + (Constants.ONE_DAY_MILLISECONDS * tokenConfig.getAccessExpirationTimeDay());

        return JWT.create()
                .withSubject(userAccount.getEmailId())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withKeyId(UUID.randomUUID().toString())
                .withExpiresAt(new Date(expiry))
                .withClaim("uid", userAccount.getUid())
                .withClaim("name", userAccount.getName())
                .withClaim("isAccountVerified", userAccount.isAccountVerified())
                .withIssuer(tokenConfig.getIssuer())
                .sign(algorithm);

    }

    public String generateRefreshToken(User user) {

        UserAccount userAccount = userService.getUserByEmailId(user.getUsername());
        return generateRefreshToken(userAccount);
    }

    public String generateRefreshToken(UserAccount userAccount) {

        long expiry = System.currentTimeMillis() + (Constants.ONE_DAY_MILLISECONDS * tokenConfig.getRefreshExpirationTimeDay());

        return JWT.create()
                .withSubject(userAccount.getEmailId())
                .withExpiresAt(new Date(expiry))
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withIssuer(tokenConfig.getIssuer())
                .withClaim("uid", userAccount.getUid())
                .withClaim(Constants.TOKEN_TYPE, Constants.REFRESH_TOKEN)
                .sign(algorithm);
    }

    public DecodedJWT isTokenValid(String token) throws JWTVerificationException {

        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        return jwtVerifier.verify(token);
    }

    public String getUsernameFromJWTToken(String token) {

        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(token);
        return decodedJWT.getSubject();
    }

}
