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

    // Convert Account entity to DTO to safely expose only non-sensitive info
    public AccountDTO toDTO() {
        return AccountDTO.builder()
                .id(this.id)
                .balance(this.balance) // Expose only allowed info, hide IBAN if required
                .build();
    }
}
