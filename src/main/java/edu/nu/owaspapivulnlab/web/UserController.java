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
 * Added rate limiting to prevent abuse of sensitive user operations.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    // ✅ In-memory bucket: limit 5 requests per minute for user-sensitive endpoints
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
     * Vulnerability Fixed: API1 (BOLA/IDOR)
     * Rate limiting applied (max 5 requests/minute)
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
        AppUserDTO dto = user.toDTO();
        return ResponseEntity.ok(dto);
    }

    /**
     * Mass Assignment prevention — ignore sensitive fields like roles/admin
     * Vulnerability Fixed: API6 (Mass Assignment)
     * Rate limiting applied (max 5 requests/minute)
     */
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        body.setRole("USER"); 
        body.setAdmin(false); 
        AppUser saved = users.save(body);
        return ResponseEntity.ok(saved.toDTO());
    }

    /**
     * Search endpoint restricted to prevent data enumeration
     * Vulnerability Fixed: API9
     * Rate limiting applied (max 5 requests/minute)
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
     * Vulnerability Fixed: API3
     * Rate limiting applied (max 5 requests/minute)
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
     * Vulnerability Fixed: API5
     * Rate limiting applied (max 5 requests/minute)
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
}
