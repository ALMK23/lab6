package ru.mtuci.translations.security;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtuci.translations.repository.UserRepository;

import java.time.Clock;
import java.time.Instant;

/** Загрузка учётной записи из БД по email (логину). */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final Clock clock;

    public AppUserDetailsService(UserRepository userRepository, Clock clock) {
        this.userRepository = userRepository;
        this.clock = clock;
    }

    @Override
    @Transactional(readOnly = true)
    public SecurityUser loadUserByUsername(String username) throws UsernameNotFoundException {
        String email = username == null ? "" : username.trim();
        return userRepository.findByEmailIgnoreCase(email)
                .map(user -> new SecurityUser(user, Instant.now(clock)))
                // текст наружу не уходит: Spring превращает это в BadCredentialsException
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }
    @Transactional(readOnly = true)
    public SecurityUser loadTokenOwner(JwtService.Owner owner) {
        SecurityUser user = loadUserByUsername(owner.username());
        if (!user.getUsername().equals(owner.username()) || user.getId() != owner.userId()
                || !user.isEnabled() || !user.isAccountNonLocked()) {
            throw new BadCredentialsException("Invalid token owner");
        }
        return user;
    }
}

