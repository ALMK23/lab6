package ru.mtuci.translations.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;
import ru.mtuci.translations.exception.ApiErrors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;

/** 403 из фильтров: нет CSRF-токена или у пользователя не хватает прав на URL. */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger(RestAccessDeniedHandler.class);

    private final ObjectMapper objectMapper;
    private final Clock clock;

    public RestAccessDeniedHandler(ObjectMapper objectMapper, Clock clock) {
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        String message;
        if (accessDeniedException instanceof CsrfException) {
            message = ApiErrors.CSRF_INVALID;
        } else {
            message = ApiErrors.ACCESS_DENIED;
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            log.warn("Отказ в доступе: пользователь '{}' -> {} {}",
                    auth == null ? "anonymous" : auth.getName(), request.getMethod(), request.getRequestURI());
        }

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getOutputStream(),
                ApiErrors.body(HttpStatus.FORBIDDEN, message, Instant.now(clock)));
    }
}
