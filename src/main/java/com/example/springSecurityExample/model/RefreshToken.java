package com.example.springSecurityExample.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Table
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor


public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String token;

    private Instant expiresAt;

    @OneToOne
    @JoinColumn(name = "username")
    private Users user;


}

