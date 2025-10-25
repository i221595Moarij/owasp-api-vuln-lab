package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    // VULNERABILITY(API3: Excessive Data Exposure): storing plaintext passwords for demo
    // FIX: Passwords should be hashed before storing. Do not expose in DTOs.
    @NotBlank
    private String password;

    // VULNERABILITY(API6: Mass Assignment): role and isAdmin are bindable via incoming JSON
    // FIX: Do not expose these in responses; handle authorization in service/controller
    private String role;   // e.g., "USER" or "ADMIN"
    private boolean isAdmin;

    @Email
    private String email;

    // Additional helper method to convert AppUser to DTO
    public AppUserDTO toDTO() {
        return AppUserDTO.builder()
                .id(this.id)
                .username(this.username)
                .email(this.email)
                .build(); // password, role, isAdmin are excluded
    }
}
