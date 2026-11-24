package ru.mtuci.translations.service;

import org.springframework.stereotype.Component;
import ru.mtuci.translations.exception.BadRequestException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Требования к паролю:
 * - от 8 символов и не больше 72 байт (BCrypt учитывает только первые 72 байта);
 * - строчная и заглавная буквы, цифра и спецсимвол;
 * - без пробелов;
 * - не содержит часть email до @ и имя пользователя;
 * - не из списка самых популярных паролей.
 */
@Component
class PasswordPolicy {

    static final int MIN_LENGTH = 8;
    static final int MAX_BYTES = 72;

    private static final Set<String> COMMON = Set.of(
            "password", "password1", "password1!", "p@ssw0rd", "qwerty123", "qwerty123!",
            "12345678", "123456789", "1234567890", "11111111", "iloveyou", "admin123", "admin123!",
            "welcome1", "welcome1!", "qwertyuiop", "1q2w3e4r", "1q2w3e4r5t", "zaq12wsx");

    void check(String password, String email, String name) {
        List<String> errors = new ArrayList<>();
        if (password == null || password.isEmpty()) {
            throw new BadRequestException("password: пароль обязателен");
        }
        if (password.length() < MIN_LENGTH) {
            errors.add("не короче " + MIN_LENGTH + " символов");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            errors.add("не длиннее " + MAX_BYTES + " байт");
        }
        if (password.chars().noneMatch(Character::isLowerCase)) {
            errors.add("нужна строчная буква");
        }
        if (password.chars().noneMatch(Character::isUpperCase)) {
            errors.add("нужна заглавная буква");
        }
        if (password.chars().noneMatch(Character::isDigit)) {
            errors.add("нужна цифра");
        }
        if (password.chars().allMatch(Character::isLetterOrDigit)) {
            errors.add("нужен спецсимвол (например ! # $ % _ -)");
        }
        if (password.chars().anyMatch(Character::isWhitespace)) {
            errors.add("пробелы не допускаются");
        }

        String lower = password.toLowerCase(Locale.ROOT);
        if (COMMON.contains(lower)) {
            errors.add("слишком распространённый пароль");
        }
        if (email != null) {
            String login = email.trim().toLowerCase(Locale.ROOT);
            int at = login.indexOf('@');
            if (at > 0) {
                login = login.substring(0, at);
            }
            if (login.length() >= 3 && lower.contains(login)) {
                errors.add("не должен содержать email");
            }
        }
        if (name != null && name.trim().length() >= 3 && lower.contains(name.trim().toLowerCase(Locale.ROOT))) {
            errors.add("не должен содержать имя");
        }

        if (!errors.isEmpty()) {
            throw new BadRequestException("password: слабый пароль — " + String.join("; ", errors));
        }
    }
}
