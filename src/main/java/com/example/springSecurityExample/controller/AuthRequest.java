package com.example.springSecurityExample.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthRequest {

    @GetMapping("/test")
    public String anyReq() {
        return "success";
    }
}
