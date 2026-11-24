package ru.mtuci.translations.security;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ru.mtuci.translations.model.Permission;
import ru.mtuci.translations.model.Role;
import ru.mtuci.translations.model.User;
import ru.mtuci.translations.model.UserStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Аутентифицированный пользователь в Spring Security.
 * Права = ROLE_<роль> + отдельные права роли (USERS_MANAGE, PROJECTS_MANAGE, ...).
 */
public class SecurityUser implements UserDetails, CredentialsContainer {

    private final Long id;
    private final String email;
    private String passwordHash;
    private final Role role;
    private final boolean active;
    private final boolean locked;
    private final int failedLoginAttempts;
    private final List<GrantedAuthority> authorities;

    public SecurityUser(User user, Instant now) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.passwordHash = user.getPasswordHash();
        this.role = user.getRole();
        this.active = user.getStatus() == UserStatus.ACTIVE;
        this.locked = user.getLockedUntil() != null && user.getLockedUntil().isAfter(now);
        this.failedLoginAttempts = user.getFailedLoginAttempts();

        List<GrantedAuthority> list = new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
        for (Permission permission : role.getPermissions()) {
            list.add(new SimpleGrantedAuthority(permission.name()));
        }
        this.authorities = List.copyOf(list);
    }

    public Long getId() {
        return id;
    }

    public Role getRole() {
        return role;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    /** Заблокирован администратором → DisabledException при входе. */
    @Override
    public boolean isEnabled() {
        return active;
    }

    /** Временно заблокирован после подбора пароля → LockedException при входе. */
    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    // срок действия учётных записей и паролей в приложении не ограничен
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /** После успешного входа хеш пароля больше не нужен — убираем его из объекта. */
    @Override
    public void eraseCredentials() {
        passwordHash = null;
    }
}
