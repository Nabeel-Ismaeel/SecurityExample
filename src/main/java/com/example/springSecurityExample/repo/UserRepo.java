package com.example.springSecurityExample.repo;

import com.example.springSecurityExample.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<Users , Integer> {
    Users findByUsername(String username);
}
