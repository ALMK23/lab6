package ru.mtuci.translations.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import ru.mtuci.translations.model.Role;
import ru.mtuci.translations.model.UserStatus;

import java.time.Instant;

public final class UserDto {

    private UserDto() {
    }

    /** Создание пользователя администратором: роль можно указать. */
    public record CreateRequest(
            @NotBlank @Size(max = 200) String name,
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank String password,
            Role role) {
    }

    /** Имя и email. Пароль, роль и статус здесь не меняются — для них отдельные операции. */
    public record PatchRequest(
            @Size(max = 200) String name,
            @Email @Size(max = 320) String email) {
    }

    public record RoleRequest(@NotNull Role role) {
    }

    /** Хеш пароля и счётчики входа наружу не отдаются. */
    public record Response(
            Long id,
            String name,
            String email,
            Role role,
            UserStatus status,
            Instant createdAt,
            Instant updatedAt) {
    }
}
