package com.rkumar0206.mymuserauthenticationservice.service;

import com.rkumar0206.mymuserauthenticationservice.config.EmailConfig;
import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock
    private EmailConfig emailConfig;

    @Mock
    private JavaMailSender javaMailSender;
    private EmailServiceImpl emailService;

    @BeforeEach
    public void setup() {

        emailService = new EmailServiceImpl(emailConfig, javaMailSender);
    }

    @Test
    void sendConfirmationToken() throws Exception {

        ConfirmationToken confirmationToken = new ConfirmationToken(
                "dsjbhsb", "test@gmail.com", "asjbajhvjav", 0L
        );

        doNothing().when(javaMailSender).send(any(SimpleMailMessage.class));

        emailService.sendConfirmationToken(confirmationToken);

        Thread.sleep(20);

        verify(javaMailSender, times(1)).send(any(SimpleMailMessage.class));

    }
}