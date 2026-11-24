package ru.mtuci.translations.exception;

import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Единый формат тела ошибки для всего API — и для контроллеров, и для фильтров Spring Security:
 * {"timestamp", "status", "error", "message"}.
 * В message — только текст для клиента, без стектрейсов, SQL и внутренних деталей.
 */
public final class ApiErrors {

    public static final String AUTH_REQUIRED = "Требуется аутентификация (HTTP Basic: email и пароль)";
    public static final String BAD_CREDENTIALS = "Неверный email или пароль, либо учётная запись заблокирована";
    public static final String ACCESS_DENIED = "Недостаточно прав для выполнения операции";
    public static final String CSRF_INVALID = "CSRF-токен отсутствует или недействителен. Получите токен: GET /api/auth/csrf";

    private ApiErrors() {
    }

    public static Map<String, Object> body(HttpStatus status, String message, Instant now) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", now);
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return body;
    }
}
