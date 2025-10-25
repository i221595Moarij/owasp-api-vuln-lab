package edu.nu.owaspapivulnlab.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccountDTO {
    private Long id;
    private Double balance;
    // IBAN and ownerUserId intentionally omitted to prevent sensitive data exposure
}
