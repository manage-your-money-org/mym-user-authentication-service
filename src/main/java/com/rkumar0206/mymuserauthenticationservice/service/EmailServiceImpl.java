package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.config.EmailConfig;
import com.rkumar0206.mymuserauthenticationservice.constantsAndEnums.Constants;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final EmailConfig emailConfig;
    private final JavaMailSender javaMailSender;

    @Value("${server.port}")
    private int port;

    @Override
    public void sendConfirmationToken(ConfirmationToken confirmationToken) throws Exception {

        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();

        simpleMailMessage.setTo(confirmationToken.getEmailId());
        simpleMailMessage.setSubject(Constants.ACCOUNT_VERIFY_MAIL_SUBJECT);
        simpleMailMessage.setFrom(emailConfig.getUsername());

        String confirmationUrl = "http://localhost:" + port + "/mym/api/users/account/verify?token=" + confirmationToken.getConfirmationToken();

        simpleMailMessage.setText(String.format(Constants.ACCOUNT_VERIFY_MAIL_TEXT, confirmationUrl));

        sendMail(simpleMailMessage);
    }

    @Override
    public SimpleMailMessage sendPasswordResetUrl(UserAccount user, String resetPasswordUrl) throws Exception {
        return null;
    }

    @Override
    public void sendMail(SimpleMailMessage mailMessage) throws Exception {

        try {

            new Thread(() -> {

                log.info("Sending mail...");
                javaMailSender.send(mailMessage);
                log.info("Mail sent successfully...");
            }).start();

        } catch (Exception e) {
            e.printStackTrace();
            log.info("Mail not sent!!");
            throw e;
        }

    }
}
