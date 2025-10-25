package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final BCryptPasswordEncoder passwordEncoder; // Added

    public AuthController(AppUserRepository users, JwtService jwt, BCryptPasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
    }

    // --- Request DTOs ---
    public static class LoginReq {
        @NotBlank private String username;
        @NotBlank private String password;

        public LoginReq() {}
        public LoginReq(String username, String password) { this.username = username; this.password = password; }

        public String username() { return username; }
        public String password() { return password; }
        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class SignupReq {
        @NotBlank private String username;
        @NotBlank private String password;
        @NotBlank private String email;

        public SignupReq() {}
        public SignupReq(String username, String password, String email) {
            this.username = username; this.password = password; this.email = email;
        }

        public String username() { return username; }
        public String password() { return password; }
        public String email() { return email; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
        public void setEmail(String email) { this.email = email; }
    }

    public static class TokenRes {
        private String token;
        public TokenRes() {}
        public TokenRes(String token) { this.token = token; }
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // --- LOGIN Endpoint ---
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        AppUser user = users.findByUsername(req.username()).orElse(null);
        // FIX: Use BCrypt to verify hashed password
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin()); // consider ignoring isAdmin for client-side
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    // --- SIGNUP Endpoint ---
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupReq req) {
        if (users.findByUsername(req.username()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "username already exists");
            return ResponseEntity.status(400).body(error);
        }
        // FIX: hash password with BCrypt before saving
        String hashedPassword = passwordEncoder.encode(req.password());
        AppUser newUser = AppUser.builder()
                .username(req.username())
                .password(hashedPassword)
                .email(req.email())
                .role("USER")
                .isAdmin(false)
                .build();
        users.save(newUser);

        Map<String, String> success = new HashMap<>();
        success.put("message", "user registered successfully");
        return ResponseEntity.ok(success);
    }
}
