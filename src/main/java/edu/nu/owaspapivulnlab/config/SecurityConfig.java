package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

/**
 * SecurityConfig — Updated to enforce strict authentication and role-based access control.
 */
@Configuration
@EnableMethodSecurity // ✅ Enables @PreAuthorize annotations for controllers
public class SecurityConfig {

    private final BCryptPasswordEncoder passwordEncoder;
    private final String secret;

    // ✅ Constructor injection for encoder and secret key
    public SecurityConfig(BCryptPasswordEncoder passwordEncoder,
                          @Value("${app.jwt.secret}") String secret) {
        this.passwordEncoder = passwordEncoder;
        this.secret = secret;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // ✅ Only authentication endpoints are public
        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll() // Allow signup/login & H2
                .requestMatchers("/api/admin/**").hasRole("ADMIN")              // Only ADMIN can access admin APIs
                .requestMatchers("/api/user/**").hasRole("USER")                // Only USER can access user APIs
                .anyRequest().authenticated()                                   // All others must be authenticated
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // For H2 console only

        // ✅ Add JWT filter for validating tokens
        http.addFilterBefore(new JwtFilter(secret),
                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Custom JWT Filter — validates JWT and sets SecurityContext.
     */
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    Claims claims = Jwts.parserBuilder()
                            .setSigningKey(secret.getBytes())
                            .build()
                            .parseClaimsJws(token)
                            .getBody();

                    String user = claims.getSubject();
                    String role = (String) claims.get("role");

                    if (user != null && role != null) {
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(
                                        user,
                                        null,
                                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                );
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                } catch (JwtException e) {
                    // Token invalid or expired — silently continue (request will fail auth)
                }
            }
            chain.doFilter(request, response);
        }
    }
}
