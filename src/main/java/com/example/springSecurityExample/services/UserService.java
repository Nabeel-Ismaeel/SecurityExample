package com.example.springSecurityExample.services;

import com.example.springSecurityExample.dto.JwtResponse;
import com.example.springSecurityExample.model.Users;
import com.example.springSecurityExample.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    JwtService jwtService;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private AuthenticationManager authenticationManager;


    public String register(Users user) {
        if (userRepo.findByUsername(user.getUsername()).isEmpty()){
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepo.save(user);
            return  "Successfully registered";
        }
        throw new UsernameNotFoundException("Username already exists");
    }


    public JwtResponse verify(Users user) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if (authentication.isAuthenticated()) {
            return JwtResponse
                    .builder()
                    .accessToken(jwtService.generateToken(user.getUsername()))
                    .refreshToken(refreshTokenService.generateRefreshToken(user.getUsername()))
                    .build();
        }
        throw new IllegalStateException("username or password is incorrect ");
    }
}
