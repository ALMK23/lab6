package ru.mtuci.translations.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import ru.mtuci.translations.exception.ApiErrors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;

/**
 * 401 — пользователь не аутентифицирован.
 * Неверный пароль, несуществующий email и заблокированная учётная запись дают ОДИНАКОВЫЙ ответ,
 * чтобы по ответу нельзя было узнать, какие email зарегистрированы и в каком они состоянии.
 * Подробности пишутся только в лог (LoginAttemptService).
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final Clock clock;

    public RestAuthenticationEntryPoint(ObjectMapper objectMapper, Clock clock) {
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // логин/пароль вообще не передавали — просто просим войти
        String message = authException instanceof InsufficientAuthenticationException
                ? ApiErrors.AUTH_REQUIRED
                : ApiErrors.BAD_CREDENTIALS;

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader("WWW-Authenticate", "Basic realm=\"translations\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getOutputStream(),
                ApiErrors.body(HttpStatus.UNAUTHORIZED, message, Instant.now(clock)));
    }
}
