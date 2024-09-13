package com.example.springSecurityExample.services;

import com.example.springSecurityExample.dto.JwtResponse;
import com.example.springSecurityExample.model.RefreshToken;
import com.example.springSecurityExample.model.Users;
import com.example.springSecurityExample.repo.RefreshTokenRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;


    public String stringHashing(String str) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(str.getBytes());
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateRefreshToken(String username) {
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .user((Users) userDetailsService.loadUserByUsername(username))
                .token(stringHashing(token))
                .expiresAt(Instant.now().plusMillis(1000 * 60 * 5))
                .build();
        refreshTokenRepo.save(refreshToken);
        return token;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().compareTo(Instant.now()) < 0) {
            refreshTokenRepo.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public JwtResponse generateNewToken(String refreshToken) {
        Optional<RefreshToken> token = refreshTokenRepo.findByToken(stringHashing(refreshToken));

        if (token.isPresent()) {
            String newAccessToken = jwtService.generateToken(
                    verifyExpiration(token.get())
                            .getUser()
                            .getUsername());

            return JwtResponse.
                    builder()
                    .accessToken(newAccessToken)
                    .refreshToken(refreshToken)
                    .build();
        } else {
            throw new IllegalStateException("Refresh token not found");
        }

    }

}
