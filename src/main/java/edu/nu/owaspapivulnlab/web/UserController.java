package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    /**
     * FIXED: Ownership enforced — user can only fetch their own info
     * Vulnerability Fixed: API1 (BOLA/IDOR)
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Ownership check
        if (!currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your user"));
        }

        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }

    /**
     * FIXED: Mass Assignment prevention — ignore sensitive fields like roles/admin
     * Vulnerability Fixed: API6 (Mass Assignment)
     */
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body) {
        // Force safe defaults for sensitive fields
        body.setRole("USER"); // ignore any role sent by client
        body.setAdmin(false);  // prevent client from assigning admin
        AppUser saved = users.save(body);
        return ResponseEntity.ok(saved);
    }

    /**
     * FIXED: Search endpoint restricted to prevent data enumeration
     * Vulnerability Fixed: API9 (Improper Inventory / Injection-style enumeration)
     */
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        // Only allow searching for own username or email
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.getUsername().contains(q)) {
            return ResponseEntity.ok(List.of()); // empty result if query doesn't match self
        }

        return ResponseEntity.ok(List.of(currentUser));
    }

    /**
     * FIXED: List all users removed for regular users (prevents excessive data exposure)
     * Vulnerability Fixed: API3
     */
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Only allow admin to list all users
        if (!currentUser.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — admin only"));
        }

        return ResponseEntity.ok(users.findAll());
    }

    /**
     * FIXED: Only admin or owner can delete account
     * Vulnerability Fixed: API5 (Broken Function Level Authorization)
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
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
