package ru.mtuci.translations.model;

import java.util.Set;

/**
 * Роли пользователей.
 * TRANSLATOR — переводчик (роль по умолчанию при регистрации);
 * EDITOR — редактор: ведёт свои проекты и согласует в них переводы, может и сам переводить в чужих проектах;
 * ADMIN — администратор: управляет пользователями, в согласовании не участвует.
 */
public enum Role {
    TRANSLATOR(Set.of(Permission.TRANSLATIONS_WRITE)),
    EDITOR(Set.of(Permission.PROJECTS_MANAGE, Permission.TRANSLATIONS_WRITE, Permission.TRANSLATIONS_REVIEW)),
    ADMIN(Set.of(Permission.USERS_MANAGE));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public boolean has(Permission permission) {
        return permissions.contains(permission);
    }
}
