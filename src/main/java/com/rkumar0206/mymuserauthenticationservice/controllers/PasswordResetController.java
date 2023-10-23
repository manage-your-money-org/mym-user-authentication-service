package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/mym/api/users")
@RequiredArgsConstructor
@Slf4j
public class PasswordResetController {

    private final UserService userService;
    private final JWT_Util jwtUtil;

    @GetMapping("/password/reset/form")
    public String passwordResetForm(
            @RequestParam("token") String token,
            @RequestParam("email") String email,
            Model model
    ) {

        try {

            jwtUtil.isTokenValid(token);
            userService.checkResetPasswordToken(email, token);

        } catch (Exception e) {

            model.addAttribute(Constants.MESSAGE, e.getMessage());
            return "reset-password-message";
        }

        model.addAttribute("token", token);
        model.addAttribute("email", email);

        return "reset-password-form";
    }

    @PostMapping("/password/reset/form/submit")
    public String passwordResetFormSubmit(
            HttpServletRequest request,
            Model model
    ) {

        try {

            String token = request.getParameter("token");
            String email = request.getParameter("email");
            String password = request.getParameter("password");

            jwtUtil.isTokenValid(token);

            userService.resetPassword(email, password);

            model.addAttribute(Constants.MESSAGE, "Your password has been changed, please log in");

        } catch (Exception e) {

            model.addAttribute(Constants.MESSAGE, e.getMessage());
        }

        return "reset-password-message";
    }


}
