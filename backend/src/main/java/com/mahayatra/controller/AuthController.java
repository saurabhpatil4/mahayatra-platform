package com.mahayatra.controller;

import com.mahayatra.entity.Role;
import com.mahayatra.entity.User;
import com.mahayatra.repository.UserRepository;
import backend.backend.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        if (userRepository.existsByEmail(request.get("email"))) {
            return ResponseEntity.badRequest().body("Email already in use");
        }

        User user = User.builder()
                .fullName(request.get("fullName"))
                .email(request.get("email"))
                .phoneNumber(request.get("phoneNumber"))
                .password(passwordEncoder.encode(request.get("password")))
                .role(Role.ROLE_USER) // Default role for standard passengers
                .build();

        userRepository.save(user);
        String jwt = jwtUtil.generateToken(user);

        return ResponseEntity.ok(Map.of(
                "token", jwt,
                "message", "User registered successfully",
                "role", user.getRole().name()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        // This will verify the password against the encoded hash in Postgres
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.get("email"), request.get("password"))
        );

        User user = userRepository.findByEmail(request.get("email")).orElseThrow();
        String jwt = jwtUtil.generateToken(user);

        return ResponseEntity.ok(Map.of(
                "token", jwt,
                "role", user.getRole().name()
        ));
    }
}