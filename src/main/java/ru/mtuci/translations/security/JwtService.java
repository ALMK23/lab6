package ru.mtuci.translations.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    public record Token(String value, Instant expiry) {}
    public record Owner(String username, long userId) {}

    private final SecretKey key;
    private final JwtParser parser;
    private final Clock clock;
    private final long accessSeconds;
    private final long refreshSeconds;

    public JwtService(@Value("${jwt.secret}") String secret, @Value("${jwt.access-seconds}") long accessSeconds,
                      @Value("${jwt.refresh-seconds}") long refreshSeconds, Clock clock) {
        byte[] bytes = Base64.getDecoder().decode(secret);
        if (bytes.length != 32 || accessSeconds <= 0 || refreshSeconds <= 0) {
            throw new IllegalArgumentException("JWT requires a 32-byte key and positive token lifetimes");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.clock = clock;
        this.accessSeconds = accessSeconds;
        this.refreshSeconds = refreshSeconds;
        this.parser = Jwts.parser().verifyWith(key).clock(() -> Date.from(clock.instant()))
                .build();
    }

    public Token issueAccess(Owner owner) { return issue(owner, "access", accessSeconds); }
    public Token issueRefresh(Owner owner) { return issue(owner, "refresh", refreshSeconds); }
    public Owner verifyAccess(String token) { return verify(token, "access"); }
    public Owner verifyRefresh(String token) { return verify(token, "refresh"); }

    private Token issue(Owner owner, String type, long seconds) {
        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiry = now.plusSeconds(seconds);
        String jwt = Jwts.builder().subject(owner.username()).id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now)).expiration(Date.from(expiry)).claim("type", type)
                .claim("uid", owner.userId()).signWith(key, Jwts.SIG.HS256).compact();
        return new Token(jwt, expiry);
    }

    private Owner verify(String token, String type) {
        try {
            var signed = parser.parseSignedClaims(token);
            if (!Jwts.SIG.HS256.getId().equals(signed.getHeader().getAlgorithm())) {
                throw new BadCredentialsException("Invalid signing algorithm");
            }
            Claims claims = signed.getPayload();
            Long userId = claims.get("uid", Long.class);
            if (!type.equals(claims.get("type")) || claims.getSubject() == null || claims.getSubject().isBlank()
                    || claims.getId() == null || claims.getId().isBlank() || userId == null
                    || claims.getIssuedAt() == null || claims.getExpiration() == null
                    || !claims.getExpiration().toInstant().isAfter(clock.instant())) {
                throw new BadCredentialsException("Invalid JWT claims");
            }
            return new Owner(claims.getSubject(), userId);
        } catch (JwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid JWT", ex);
        }
    }
}

