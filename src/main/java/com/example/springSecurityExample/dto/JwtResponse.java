package com.example.springSecurityExample.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class JwtResponse {
    private String accessToken;
    private String refreshToken;
}
