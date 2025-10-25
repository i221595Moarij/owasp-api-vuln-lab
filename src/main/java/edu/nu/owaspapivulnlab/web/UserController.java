package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.AppUserDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import io.github.bucket4j.Bandwidth;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * UserController — user management endpoints
 *
 * Added:
 * 1. Rate limiting using Bucket4j.
 * 2. Ownership checks for sensitive user operations.
 * 3. Mass Assignment prevention via DTOs.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    private final Bucket bucket;

    public UserController(AppUserRepository users) {
        this.users = users;
        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        this.bucket = Bucket4j.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Enforced ownership — user can only fetch their own info
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your user"));
        }

        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user.toDTO());
    }

    /**
     * Mass Assignment prevention — only allows safe fields via CreateUserDTO
     */
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserDTO body) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        // Only allowed fields are copied from DTO
        AppUser newUser = new AppUser();
        newUser.setUsername(body.getUsername());
        newUser.setPassword(body.getPassword()); // assume password is hashed in service or entity
        newUser.setRole("USER");  // explicitly set, cannot be overridden
        newUser.setAdmin(false);  // explicitly set, cannot be overridden

        AppUser saved = users.save(newUser);
        return ResponseEntity.ok(saved.toDTO());
    }

    /**
     * Search endpoint restricted to prevent data enumeration
     */
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.getUsername().contains(q)) {
            return ResponseEntity.ok(List.of());
        }

        List<AppUserDTO> result = List.of(currentUser.toDTO());
        return ResponseEntity.ok(result);
    }

    /**
     * List all users removed for regular users (prevents excessive data exposure)
     */
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — admin only"));
        }

        List<AppUserDTO> allUsers = users.findAll()
                .stream()
                .map(AppUser::toDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(allUsers);
    }

    /**
     * Only admin or owner can delete account
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin() && !currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — cannot delete this user"));
        }

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }

    /**
     * DTO for creating users — prevents mass assignment
     */
    public static class CreateUserDTO {
        private String username;
        private String password;

        public String getUsername() {
            return username;
        }
        public void setUsername(String username) {
            this.username = username;
        }
        public String getPassword() {
            return password;
        }
        public void setPassword(String password) {
            this.password = password;
        }
    }
}
