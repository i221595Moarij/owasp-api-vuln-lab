package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    // Load secret from environment variable for strong key management
    @Value("${app.jwt.secret}")
    private String secret;

    // Short TTL in seconds (e.g., 300 = 5 minutes)
    @Value("${app.jwt.ttl-seconds:300}")
    private long ttlSeconds;

    // Optional: define issuer and audience for token validation
    @Value("${app.jwt.issuer:owasp-api-vuln-lab}")
    private String issuer;

    @Value("${app.jwt.audience:owasp-api-users}")
    private String audience;

    /**
     * Issue JWT with:
     * - Strong key from env
     * - Short TTL
     * - Issuer and Audience
     * - HS256 signature
     */
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .setIssuer(issuer)
                .setAudience(audience)
                .signWith(SignatureAlgorithm.HS256, secret.getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    /**
     * Extract username (subject) safely
     * Validates signature, expiry, issuer, and audience strictly
     */
    public String extractUsername(String token) throws JwtException {
        Claims claims = parseToken(token).getBody();
        return claims.getSubject();
    }

    /**
     * Extract any custom claim safely
     */
    public Object extractClaim(String token, String key) throws JwtException {
        Claims claims = parseToken(token).getBody();
        return claims.get(key);
    }

    /**
     * Centralized JWT parsing with strict validation:
     * - Signature check
     * - Expiry check
     * - Issuer and Audience verification
     */
    private Jws<Claims> parseToken(String token) throws JwtException {
        return Jwts.parser()
                .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                .requireIssuer(issuer)
                .requireAudience(audience)
                .parseClaimsJws(token);
    }
}