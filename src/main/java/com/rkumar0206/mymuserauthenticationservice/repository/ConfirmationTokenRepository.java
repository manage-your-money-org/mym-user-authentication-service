package com.rkumar0206.mymuserauthenticationservice.repository;

import com.rkumar0206.mymuserauthenticationservice.domain.ConfirmationToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConfirmationTokenRepository extends MongoRepository<ConfirmationToken, String> {
}
