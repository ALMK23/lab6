package ru.mtuci.translations.controller;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.security.JwtService;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.TokenSessionService;
import ru.mtuci.translations.service.TokenSessionService.Pair;

@RestController
@RequestMapping("/auth")
public class TokenController {
    public record Login(@JsonAlias("username") @NotBlank String email, @NotBlank String password, String deviceId) {}
    public record Register(@NotBlank @Size(max = 200) String name, @NotBlank @Email @Size(max = 320) String email,
                           @NotBlank String password, String deviceId) {}
    public record Refresh(@NotBlank String refreshToken) {
        @JsonAnySetter
        public void rejectUnknownField(String name, Object value) {
            throw new IllegalArgumentException("Only refreshToken is accepted");
        }
    }

    private final AuthenticationManager authentication;
    private final TokenSessionService sessions;

    public TokenController(AuthenticationManager authentication, TokenSessionService sessions) {
        this.authentication = authentication;
        this.sessions = sessions;
    }

    @PostMapping("/login")
    public Pair login(@Valid @RequestBody Login request) {
        var result = authentication.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(
                request.email(), request.password()));
        var user = (SecurityUser) result.getPrincipal();
        return sessions.issue(new JwtService.Owner(user.getUsername(), user.getId()), request.deviceId());
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Pair register(@Valid @RequestBody Register request) {
        return sessions.register(request.name(), request.email(), request.password(), request.deviceId());
    }

    @PostMapping("/refresh")
    public Pair refresh(@Valid @RequestBody Refresh request) {
        return sessions.rotate(request.refreshToken()).orElseThrow(() -> new BadCredentialsException("Inactive session"));
    }
}
