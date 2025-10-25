package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    /**
     * FIXED: Enforced Ownership — user can only view their own account balance.
     * Vulnerability Fixed: Broken Object Level Authorization (BOLA / API1)
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        // Fetch logged-in user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Ownership check
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        return ResponseEntity.ok(Map.of("balance", account.getBalance()));
    }

    /**
     * FIXED: Added ownership check before allowing transfer.
     * Vulnerabilities Fixed:
     * - API1: Broken Object Level Authorization
     * - API5: Broken Function Level Authorization (ownership)
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        // Get current user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Ownership check before transfer
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        // Simple logic to adjust balance (for demo only)
        if (account.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
        }

        account.setBalance(account.getBalance() - amount);
        accounts.save(account);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", account.getBalance());
        return ResponseEntity.ok(response);
    }

    /**
     * FIXED: Cleaned up /mine endpoint to ensure it only returns user’s own accounts.
     * (Previously could leak too much information.)
     */
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        AppUser me = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(accounts.findByOwnerUserId(me.getId()));
    }
}
