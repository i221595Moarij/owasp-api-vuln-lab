package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AccountDTO;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
     * Enforced Ownership — user can only view their own account balance.
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

        // Return as DTO to avoid exposing sensitive fields
        AccountDTO dto = account.toDTO();
        return ResponseEntity.ok(dto);
    }

    /**
     * Added ownership check before allowing transfer.
     * Vulnerabilities Fixed:
     * - API1: Broken Object Level Authorization
     * - API5: Broken Function Level Authorization (ownership)
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Ownership check
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        if (account.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
        }

        account.setBalance(account.getBalance() - amount);
        accounts.save(account);

        // Return updated balance safely
        AccountDTO dto = account.toDTO();
        return ResponseEntity.ok(Map.of("status", "ok", "account", dto));
    }

    /**
     * Returns all accounts of the logged-in user as DTOs.
     * FIX: Prevents excessive data exposure (API3)
     */
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        AppUser me = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<AccountDTO> myAccounts = accounts.findByOwnerUserId(me.getId())
                .stream()
                .map(Account::toDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(myAccounts);
    }
}
