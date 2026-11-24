package ru.mtuci.translations.dto;

import jakarta.validation.constraints.NotBlank;
import ru.mtuci.translations.model.ProjectStatus;

import java.time.Instant;

public final class TranslationProjectDto {

    private TranslationProjectDto() {
    }

    /** Владелец не передаётся — им становится текущий пользователь. */
    public record CreateRequest(
            @NotBlank String name,
            @NotBlank String targetLanguage,
            ProjectStatus status) {
    }

    /** ownerId — передать проект другому редактору. */
    public record PatchRequest(
            String name,
            String targetLanguage,
            Long ownerId,
            ProjectStatus status) {
    }

    public record Response(
            Long id,
            String name,
            String targetLanguage,
            Long ownerId,
            ProjectStatus status,
            Instant createdAt,
            Instant updatedAt) {
    }
}
