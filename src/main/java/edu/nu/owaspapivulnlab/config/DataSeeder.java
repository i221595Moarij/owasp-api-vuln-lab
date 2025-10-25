package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Import BCrypt
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@Configuration
public class DataSeeder {

    // Bean for password encoding, so it can be reused anywhere
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, BCryptPasswordEncoder encoder) {
        return args -> {
            if (users.count() == 0) {
                // Hash passwords before saving to database
                String alicePassword = encoder.encode("alice123");
                String bobPassword = encoder.encode("bob123");

                AppUser u1 = users.save(
                        AppUser.builder()
                                .username("alice")
                                .password(alicePassword) // store hashed password
                                .email("alice@cydea.tech")
                                .role("USER")
                                .isAdmin(false)
                                .build()
                );

                AppUser u2 = users.save(
                        AppUser.builder()
                                .username("bob")
                                .password(bobPassword) // store hashed password
                                .email("bob@cydea.tech")
                                .role("ADMIN")
                                .isAdmin(true)
                                .build()
                );

                // Create accounts linked to users
                accounts.save(Account.builder()
                        .ownerUserId(u1.getId())
                        .iban("PK00-ALICE")
                        .balance(1000.0)
                        .build());

                accounts.save(Account.builder()
                        .ownerUserId(u2.getId())
                        .iban("PK00-BOB")
                        .balance(5000.0)
                        .build());
            }
        };
    }
}
