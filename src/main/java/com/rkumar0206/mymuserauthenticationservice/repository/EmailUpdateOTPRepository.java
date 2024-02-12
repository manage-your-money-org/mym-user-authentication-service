package com.rkumar0206.mymuserauthenticationservice.repository;

import com.rkumar0206.mymuserauthenticationservice.domain.EmailUpdateOTP;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailUpdateOTPRepository extends MongoRepository<EmailUpdateOTP, String> {

    Optional<EmailUpdateOTP> findByOldEmailId(String oldEmailId);
}
