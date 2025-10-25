package edu.nu.owaspapivulnlab.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AppUserDTO {
    private Long id;
    private String username;
    private String email;
    // password, role, isAdmin are intentionally omitted to prevent exposure
}
