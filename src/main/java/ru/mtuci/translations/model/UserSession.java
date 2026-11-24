package ru.mtuci.translations.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false, length = 320)
    private String username;
    @Column(name = "device_id", columnDefinition = "text")
    private String deviceId;
    @Column(name = "access_token", nullable = false, columnDefinition = "text")
    private String accessToken;
    @Column(name = "refresh_token", nullable = false, unique = true, columnDefinition = "text")
    private String refreshToken;
    @Column(name = "access_token_expiry", nullable = false)
    private Instant accessTokenExpiry;
    @Column(name = "refresh_token_expiry", nullable = false)
    private Instant refreshTokenExpiry;
    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private SessionStatus status;

    protected UserSession() {}

    public UserSession(String username, String deviceId, String accessToken, Instant accessTokenExpiry,
                       String refreshToken, Instant refreshTokenExpiry) {
        this.username = username;
        this.deviceId = deviceId;
        this.accessToken = accessToken;
        this.accessTokenExpiry = accessTokenExpiry;
        this.refreshToken = refreshToken;
        this.refreshTokenExpiry = refreshTokenExpiry;
        this.status = SessionStatus.ACTIVE;
    }

    public String getUsername() { return username; }
    public String getDeviceId() { return deviceId; }
    public Instant getRefreshTokenExpiry() { return refreshTokenExpiry; }
    public SessionStatus getStatus() { return status; }
    public void markUsed() { status = SessionStatus.USED; }
    public void revoke() { status = SessionStatus.REVOKED; }
}
