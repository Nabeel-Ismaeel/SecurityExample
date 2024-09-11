package com.example.springSecurityExample.controller;

import com.example.springSecurityExample.dto.JwtResponse;
import com.example.springSecurityExample.model.Users;
import com.example.springSecurityExample.services.RefreshTokenService;
import com.example.springSecurityExample.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/permitted")
public class PermittedRequest {

    @Autowired
    private UserService userService;
    @Autowired
    private RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public Users addUser(@RequestBody Users user) {
        return userService.register(user);
    }

    @PostMapping("/login")
    public JwtResponse login(@RequestBody Users user) {
        return userService.verify(user);
    }

    @PostMapping("/refreshToken")
    public JwtResponse generateNewToken(@RequestBody String token) {
        return refreshTokenService.generateNewToken(token);
    }
}
