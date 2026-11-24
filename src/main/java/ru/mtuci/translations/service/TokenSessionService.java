package ru.mtuci.translations.service;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtuci.translations.model.*;
import ru.mtuci.translations.repository.UserSessionRepository;
import ru.mtuci.translations.security.*;
import java.time.Clock;
import java.util.Optional;

@Service
public class TokenSessionService {
    public record Pair(String accessToken, String refreshToken) {}

    private final JwtService jwt;
    private final UserSessionRepository sessions;
    private final UserService users;
    private final AppUserDetailsService details;
    private final Clock clock;

    public TokenSessionService(JwtService jwt, UserSessionRepository sessions, UserService users,
                               AppUserDetailsService details, Clock clock) {
        this.jwt = jwt;
        this.sessions = sessions;
        this.users = users;
        this.details = details;
        this.clock = clock;
    }

    @Transactional
    public Pair register(String name, String email, String password, String deviceId) {
        User user = users.register(name, email, password);
        return issue(new JwtService.Owner(user.getEmail(), user.getId()), deviceId);
    }

    @Transactional
    public Pair issue(JwtService.Owner owner, String deviceId) {
        var access = jwt.issueAccess(owner);
        var refresh = jwt.issueRefresh(owner);
        sessions.saveAndFlush(new UserSession(owner.username(), deviceId, access.value(), access.expiry(),
                refresh.value(), refresh.expiry()));
        return new Pair(access.value(), refresh.value());
    }

    @Transactional
    public Optional<Pair> rotate(String token) {
        var owner = jwt.verifyRefresh(token);
        var session = sessions.findByRefreshToken(token).orElseThrow(() -> new BadCredentialsException("Unknown session"));
        if (!session.getRefreshTokenExpiry().isAfter(clock.instant()) || !owner.username().equals(session.getUsername())) {
            return Optional.empty();
        }
        if (session.getStatus() == SessionStatus.USED) {
            session.revoke();
            return Optional.empty(); // commit before the controller returns 401
        }
        if (session.getStatus() != SessionStatus.ACTIVE) {
            return Optional.empty();
        }
        details.loadTokenOwner(owner);
        session.markUsed();
        return Optional.of(issue(owner, session.getDeviceId()));
    }
}
