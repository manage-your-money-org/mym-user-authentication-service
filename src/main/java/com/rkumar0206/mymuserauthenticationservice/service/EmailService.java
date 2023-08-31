package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import org.springframework.mail.SimpleMailMessage;

public interface EmailService {

    void sendConfirmationToken(ConfirmationToken confirmationToken) throws Exception;

    SimpleMailMessage sendPasswordResetUrl(UserAccount user, String resetPasswordUrl) throws Exception;

    void sendMail(SimpleMailMessage mailMessage) throws Exception;
}
