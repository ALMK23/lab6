package ru.mtuci.translations.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtuci.translations.repository.UserRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Защита от подбора пароля.
 * После MAX_ATTEMPTS неверных паролей подряд учётная запись блокируется на LOCK_TIME.
 * Пока блокировка действует, вход не проходит даже с правильным паролем.
 * Все неудачные входы пишутся в лог.
 */
@Service
public class LoginAttemptService {

    static final int MAX_ATTEMPTS = 5;
    static final Duration LOCK_TIME = Duration.ofMinutes(15);

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final UserRepository userRepository;
    private final Clock clock;

    public LoginAttemptService(UserRepository userRepository, Clock clock) {
        this.userRepository = userRepository;
        this.clock = clock;
    }

    @EventListener
    @Transactional
    public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        String email = event.getAuthentication().getName();
        userRepository.findByEmailIgnoreCase(email == null ? "" : email.trim()).ifPresentOrElse(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            if (attempts >= MAX_ATTEMPTS) {
                user.setLockedUntil(Instant.now(clock).plus(LOCK_TIME));
                user.setFailedLoginAttempts(0);
                log.warn("Учётная запись id={} временно заблокирована: {} неверных паролей подряд", user.getId(), attempts);
            } else {
                user.setFailedLoginAttempts(attempts);
                log.warn("Неверный пароль для пользователя id={} (попытка {})", user.getId(), attempts);
            }
        }, () -> log.warn("Попытка входа под несуществующим логином '{}'", clean(email)));
    }

    @EventListener
    public void onLocked(AuthenticationFailureLockedEvent event) {
        log.warn("Попытка входа во временно заблокированную учётную запись '{}'", clean(event.getAuthentication().getName()));
    }

    @EventListener
    public void onDisabled(AuthenticationFailureDisabledEvent event) {
        log.warn("Попытка входа в заблокированную администратором учётную запись '{}'", clean(event.getAuthentication().getName()));
    }

    /** Успешный вход сбрасывает счётчик (в БД пишем только если было что сбрасывать). */
    @EventListener
    @Transactional
    public void onSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication().getPrincipal() instanceof SecurityUser principal
                && principal.getFailedLoginAttempts() > 0) {
            userRepository.resetFailedLoginAttempts(principal.getId());
        }
    }

    /** Логин приходит от клиента — убираем переводы строк, чтобы нельзя было подделать записи в логе. */
    private static String clean(String value) {
        return value == null ? "" : value.replaceAll("[\\r\\n\\t]", "_");
    }
}
