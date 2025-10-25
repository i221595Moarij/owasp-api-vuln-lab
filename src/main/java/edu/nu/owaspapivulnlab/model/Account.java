package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long ownerUserId; // VULNERABILITY(API3: Excessive Data Exposure): linking to user
    private String iban;       // sensitive account info
    private Double balance;    // sensitive financial info

    /**
     * ✅ Secure setter for balance
     * Prevents setting a negative or excessively large balance value.
     * Adds defense-in-depth against direct or indirect misuse of setBalance().
     */
    public void setBalance(Double balance) {
        if (balance == null) {
            throw new IllegalArgumentException("Balance cannot be null");
        }

        // ✅ Reject negative balances
        if (balance < 0) {
            throw new IllegalArgumentException("Balance cannot be negative");
        }

        // ✅ Reject unreasonably large balances (e.g., > 10,000,000)
        if (balance > 10_000_000) {
            throw new IllegalArgumentException("Balance too large — possible overflow or logic abuse");
        }

        this.balance = balance;
    }

    /**
     * Convert Account entity to DTO
     * Only exposes safe, non-sensitive data.
     */
    public AccountDTO toDTO() {
        return AccountDTO.builder()
                .id(this.id)
                .balance(this.balance)
                .build();
    }
}
