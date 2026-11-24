package ru.mtuci.translations.security;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
    private final String key = Base64.getEncoder().encodeToString(Jwts.SIG.HS256.key().build().getEncoded());
    private final Instant now = Instant.parse("2026-01-01T12:00:00Z");
    private final JwtService.Owner owner = new JwtService.Owner("test@example.com", 1);

    private JwtService service(Instant at) {
        return new JwtService(key, 60, 600, Clock.fixed(at, ZoneOffset.UTC));
    }

    @Test
    void expiryIsExclusiveForBothTokenTypes() {
        var jwt = service(now.plusMillis(321));
        var access = jwt.issueAccess(owner);
        var refresh = jwt.issueRefresh(owner);
        assertEquals(now.plusSeconds(60), access.expiry());
        assertEquals(now.plusSeconds(600), refresh.expiry());
        assertEquals(owner, service(access.expiry().minusSeconds(1)).verifyAccess(access.value()));
        assertEquals(owner, service(refresh.expiry().minusSeconds(1)).verifyRefresh(refresh.value()));
        assertThrows(BadCredentialsException.class, () -> service(access.expiry()).verifyAccess(access.value()));
        assertThrows(BadCredentialsException.class, () -> service(refresh.expiry()).verifyRefresh(refresh.value()));
    }

    @Test
    void refreshRequiresEveryClaimAndTheSigningKey() {
        var jwt = service(now);
        var otherKey = Jwts.SIG.HS256.key().build();
        var signedByOther = new JwtService(Base64.getEncoder().encodeToString(otherKey.getEncoded()),
                60, 600, Clock.fixed(now, ZoneOffset.UTC)).issueRefresh(owner);
        assertThrows(BadCredentialsException.class, () -> jwt.verifyRefresh(signedByOther.value()));
        for (String claim : new String[]{"sub", "type", "uid", "iat", "exp", "jti"}) {
            var builder = Jwts.builder().subject(owner.username()).claim("uid", owner.userId())
                    .issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(600)))
                    .claim("type", "refresh").id("test-id");
            builder.claim(claim, null);
            var token = builder.signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                    Base64.getDecoder().decode(key)), Jwts.SIG.HS256).compact();
            assertThrows(BadCredentialsException.class, () -> jwt.verifyRefresh(token), claim);
        }
    }
}

