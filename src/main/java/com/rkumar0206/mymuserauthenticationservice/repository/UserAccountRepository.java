package com.rkumar0206.mymuserauthenticationservice.repository;

import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAccountRepository extends MongoRepository<UserAccount, String> {

    Optional<UserAccount> findByEmailId(String emailId);
}
