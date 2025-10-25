package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.AppUserDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    /**
     * Enforced ownership — user can only fetch their own info
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
        AppUserDTO dto = user.toDTO(); // Convert to DTO to hide sensitive fields
        return ResponseEntity.ok(dto);
    }

    /**
     * Mass Assignment prevention — ignore sensitive fields like roles/admin
     * Vulnerability Fixed: API6 (Mass Assignment)
     */
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body) {
        // Force safe defaults for sensitive fields
        body.setRole("USER"); 
        body.setAdmin(false); 
        AppUser saved = users.save(body);

        // Return as DTO to avoid exposing password/role/admin
        return ResponseEntity.ok(saved.toDTO());
    }

    /**
     * Search endpoint restricted to prevent data enumeration
     * Vulnerability Fixed: API9
     */
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.getUsername().contains(q)) {
            return ResponseEntity.ok(List.of()); // empty result if query doesn't match self
        }

        // Return as DTO
        List<AppUserDTO> result = List.of(currentUser.toDTO());
        return ResponseEntity.ok(result);
    }

    /**
     * List all users removed for regular users (prevents excessive data exposure)
     * Vulnerability Fixed: API3
     */
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — admin only"));
        }

        // Return all users as DTOs
        List<AppUserDTO> allUsers = users.findAll()
                .stream()
                .map(AppUser::toDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(allUsers);
    }

    /**
     * Only admin or owner can delete account
     * Vulnerability Fixed: API5
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
