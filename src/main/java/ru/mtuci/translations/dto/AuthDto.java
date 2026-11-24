package ru.mtuci.translations.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthDto {

    private AuthDto() {
    }

    /** Регистрации роль не передаётся: новый пользователь всегда TRANSLATOR. */
    public record RegisterRequest(
            @NotBlank @Size(max = 200) String name,
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank String password) {
    }

    public record ChangePasswordRequest(
            @NotBlank String currentPassword,
            @NotBlank String newPassword) {
    }

    /** CSRF-токен: передавать в заголовке headerName во всех POST / PUT / PATCH / DELETE. */
    public record CsrfResponse(String headerName, String parameterName, String token) {
    }
}
