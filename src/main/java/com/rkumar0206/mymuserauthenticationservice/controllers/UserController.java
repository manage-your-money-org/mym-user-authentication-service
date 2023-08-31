package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.ErrorMessageConstants;
import com.rkumar0206.mymuserauthenticationservice.model.request.UserAccountRequest;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import com.rkumar0206.mymuserauthenticationservice.model.response.UserAccountResponse;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/mym/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @PostMapping("/create")
    public ResponseEntity<CustomResponse<UserAccountResponse>> createUser(
            @RequestBody UserAccountRequest userAccountRequest
    ) {

        CustomResponse<UserAccountResponse> response = new CustomResponse<>();

        if (userAccountRequest.isValid()) {

            try {

                UserAccountResponse accountResponse = userService.createUser(userAccountRequest);

                response.setCode(HttpStatus.CREATED.value());
                response.setMessage(String.format(Constants.SUCCESS_, "User created successfully. Please check you email for email verification."));
                response.setBody(accountResponse);

                log.info("User created successfully");

            } catch (Exception ex) {

                response.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
                response.setMessage(String.format(Constants.FAILED_, ex.getMessage()));

                log.info("Exception occurred while creating user.\n"+ex.getMessage());
            }

        } else {

            response.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setMessage(String.format(Constants.FAILED_, ErrorMessageConstants.INVALID_USER_DETAILS_ERROR));
            log.info("Invalid user details sent for creating user.\n" + userAccountRequest);
        }

        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }
}