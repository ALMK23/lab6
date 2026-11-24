package ru.mtuci.translations.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtuci.translations.exception.BadRequestException;
import ru.mtuci.translations.exception.ConflictException;
import ru.mtuci.translations.model.ProjectStatus;
import ru.mtuci.translations.model.Role;
import ru.mtuci.translations.model.User;
import ru.mtuci.translations.model.UserStatus;
import ru.mtuci.translations.repository.TranslationProjectRepository;
import ru.mtuci.translations.repository.UserRepository;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final TranslationProjectRepository projectRepository;
    private final Lookup lookup;
    private final Clock clock;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;

    public UserService(UserRepository userRepository, TranslationProjectRepository projectRepository,
                       Lookup lookup, Clock clock, PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy) {
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
        this.lookup = lookup;
        this.clock = clock;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
    }

    public List<User> findAll() {
        return userRepository.findAllByOrderByIdAsc();
    }

    public User findById(Long id) {
        return lookup.user(id);
    }

    /**
     * Самостоятельная регистрация. Роль всегда TRANSLATOR — повышенные права можно получить
     * только от администратора. Даже если в JSON передать "role": "ADMIN", поле будет проигнорировано.
     */
    @Transactional
    public User register(String name, String email, String password) {
        return createAccount(name, email, password, Role.TRANSLATOR);
    }

    /** Создание пользователя администратором — с любой ролью. */
    @Transactional
    public User create(String name, String email, String password, Role role) {
        return createAccount(name, email, password, role != null ? role : Role.TRANSLATOR);
    }

    @Transactional
    public User update(Long id, String name, String email) {
        User user = lookup.user(id);
        if (name != null) {
            Validation.requireNotBlank(name, "name");
            user.setName(name.trim());
        }
        if (email != null) {
            Validation.requireNotBlank(email, "email");
            requireUniqueEmail(email, id);
            user.setEmail(email.trim());
        }
        user.setUpdatedAt(Instant.now(clock));
        return userRepository.saveAndFlush(user);
    }

    /** Смена своего пароля: нужен текущий пароль, новый проходит те же проверки, что и при регистрации. */
    @Transactional
    public void changePassword(Long id, String currentPassword, String newPassword) {
        User user = lookup.user(id);
        if (currentPassword == null || !passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new BadRequestException("currentPassword: текущий пароль указан неверно");
        }
        if (currentPassword.equals(newPassword)) {
            throw new BadRequestException("newPassword: новый пароль должен отличаться от текущего");
        }
        passwordPolicy.check(newPassword, user.getEmail(), user.getName());
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(Instant.now(clock));
    }

    /**
     * Смена роли администратором.
     * Нельзя менять роль самому себе (иначе можно остаться без администраторов),
     * и нельзя забрать роль редактора, пока у него есть незаархивированные проекты —
     * они остались бы без редактора, который их согласует.
     */
    @Transactional
    public User changeRole(Long id, Role role, Long actorId) {
        if (id.equals(actorId)) {
            throw new ConflictException("Нельзя изменить роль самому себе");
        }
        User user = lookup.user(id);
        if (user.getRole() == Role.EDITOR && role != Role.EDITOR
                && projectRepository.existsByOwnerIdAndStatusNot(id, ProjectStatus.ARCHIVED)) {
            throw new ConflictException("У пользователя id=" + id
                    + " есть незаархивированные проекты — сначала передайте их другому редактору");
        }
        user.setRole(role);
        user.setUpdatedAt(Instant.now(clock));
        return userRepository.saveAndFlush(user);
    }

    @Transactional
    public User block(Long id, Long actorId) {
        if (id.equals(actorId)) {
            throw new ConflictException("Нельзя заблокировать самого себя");
        }
        User user = lookup.user(id);
        user.setStatus(UserStatus.BLOCKED);
        user.setUpdatedAt(Instant.now(clock));
        return userRepository.saveAndFlush(user);
    }

    /** Разблокировка снимает и блокировку администратора, и временную блокировку после подбора пароля. */
    @Transactional
    public User unblock(Long id) {
        User user = lookup.user(id);
        user.setStatus(UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedAt(Instant.now(clock));
        return userRepository.saveAndFlush(user);
    }

    /**
     * Удаление пользователя. Его проекты (со всем содержимым) и его переводы (с замечаниями)
     * удаляются каскадно внешними ключами ON DELETE CASCADE — недействительных ссылок не остаётся.
     * Нельзя удалить автора, чьи переводы уже вошли в чужой проект на финальной стадии, и самого себя.
     */
    @Transactional
    public void delete(Long id, Long actorId) {
        if (id.equals(actorId)) {
            throw new ConflictException("Нельзя удалить собственную учётную запись");
        }
        User user = lookup.user(id);
        if (userRepository.hasTranslationsInFinishedForeignProjects(id)) {
            throw new ConflictException("Пользователь id=" + id
                    + " — автор переводов в проектах на стадии REVIEW/COMPLETED/ARCHIVED, удалить его нельзя");
        }
        userRepository.delete(user);
    }

    private User createAccount(String name, String email, String password, Role role) {
        requireUniqueEmail(email, null);
        passwordPolicy.check(password, email, name);
        User user = new User();
        user.setName(name.trim());
        user.setEmail(email.trim());
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole(role);
        user.setStatus(UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        Instant now = Instant.now(clock);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return userRepository.saveAndFlush(user);
    }

    private void requireUniqueEmail(String email, Long selfId) {
        userRepository.findByEmailIgnoreCase(email.trim())
                .filter(existing -> !existing.getId().equals(selfId))
                .ifPresent(existing -> {
                    throw new ConflictException("Пользователь с email " + email.trim() + " уже существует");
                });
    }
}
