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
 * Added:
 * 1. Rate limiting using Bucket4j.
 * 2. Ownership checks for account operations.
 * 3. **Mass Assignment prevention**: only allows client to send allowed fields in requests.
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

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
     * Get balance for an account (ownership enforced)
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

        return ResponseEntity.ok(account.toDTO());
    }

    /**
     * Transfer amount from an account (ownership enforced)
     * Mass Assignment Prevention:
     * - We only accept 'amount' as input
     * - Sensitive fields like balance, role, or ownerUserId cannot be modified via request
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id,
                                      @RequestBody TransferRequestDTO transferRequest,
                                      Authentication auth) {

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

        if (account.getBalance() < transferRequest.getAmount()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
        }

        // Update balance safely, no mass assignment
        account.setBalance(account.getBalance() - transferRequest.getAmount());
        accounts.save(account);

        return ResponseEntity.ok(Map.of("status", "ok", "account", account.toDTO()));
    }

    /**
     * Returns all accounts of the logged-in user as DTOs.
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

    /**
     * DTO class for transfer requests
     * Only allows 'amount' to be set by client — prevents mass assignment
     */
    public static class TransferRequestDTO {
        private Double amount;

        public Double getAmount() {
            return amount;
        }

        public void setAmount(Double amount) {
            this.amount = amount;
        }
    }
}
