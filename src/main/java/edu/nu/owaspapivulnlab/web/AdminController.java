package edu.nu.owaspapivulnlab.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import io.github.bucket4j.Bandwidth;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * AdminController — ADMIN-only endpoints.
 * 
 * Added rate limiting to sensitive endpoints using Bucket4j.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // ✅ In-memory bucket: limit 5 requests per minute
    private final Bucket bucket;

    public AdminController() {
        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        this.bucket = Bucket4j.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * FIX: Only ADMIN can access metrics
     * Vulnerability Fixed: API7 (Security Misconfiguration)
     * Rate limiting applied to avoid abuse (max 5 requests/minute)
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/metrics")
    public Map<String, Object> metrics() {

        // Rate limiting check
        if (!bucket.tryConsume(1)) {
            throw new TooManyRequestsException();
        }

        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> metricsMap = new HashMap<>();
        metricsMap.put("uptimeMs", rt.getUptime());
        metricsMap.put("javaVersion", System.getProperty("java.version"));
        metricsMap.put("threads", ManagementFactory.getThreadMXBean().getThreadCount());
        return metricsMap;
    }

    // Custom exception for 429 response
    static class TooManyRequestsException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
