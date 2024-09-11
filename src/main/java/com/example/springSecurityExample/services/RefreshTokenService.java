package com.example.springSecurityExample.services;

import com.example.springSecurityExample.dto.JwtResponse;
import com.example.springSecurityExample.model.RefreshToken;
import com.example.springSecurityExample.repo.RefreshTokenRepo;
import com.example.springSecurityExample.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private UserRepo userRepo;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;

    public RefreshToken generateRefreshToken(String username) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(userRepo.findByUsername(username))
                .token(UUID.randomUUID().toString())
                .expiresAt(Instant.now().plusMillis(1000 * 60 * 5))
                .build();
        return refreshTokenRepo.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().compareTo(Instant.now()) < 0) {
            refreshTokenRepo.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public JwtResponse generateNewToken(String refreshToken) {
        Optional<RefreshToken> token = refreshTokenRepo.findByToken(refreshToken);

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
