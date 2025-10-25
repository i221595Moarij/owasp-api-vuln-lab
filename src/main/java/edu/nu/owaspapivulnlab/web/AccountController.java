package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AccountDTO;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import io.github.bucket4j.Bandwidth;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * AccountController — account management endpoints
 * 
 * Added rate limiting to prevent abuse of sensitive account operations.
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    // ✅ In-memory bucket: limit 5 requests per minute for account-sensitive endpoints
    private final Bucket bucket;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;

        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        this.bucket = Bucket4j.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Enforced Ownership — user can only view their own account balance.
     * Vulnerability Fixed: Broken Object Level Authorization (BOLA / API1)
     * Rate limiting applied (max 5 requests/minute)
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        AccountDTO dto = account.toDTO();
        return ResponseEntity.ok(dto);
    }

    /**
     * Added ownership check before allowing transfer.
     * Vulnerabilities Fixed:
     * - API1: Broken Object Level Authorization
     * - API5: Broken Function Level Authorization (ownership)
     * Rate limiting applied (max 5 requests/minute)
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        if (account.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
        }

        account.setBalance(account.getBalance() - amount);
        accounts.save(account);

        AccountDTO dto = account.toDTO();
        return ResponseEntity.ok(Map.of("status", "ok", "account", dto));
    }

    /**
     * Returns all accounts of the logged-in user as DTOs.
     * FIX: Prevents excessive data exposure (API3)
     * Rate limiting applied (max 5 requests/minute)
     */
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {

        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — try again later"));
        }

        AppUser me = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<AccountDTO> myAccounts = accounts.findByOwnerUserId(me.getId())
                .stream()
                .map(Account::toDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(myAccounts);
    }
}
