package ru.mtuci.translations.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Тела запросов бизнес-операций.
 * Пользователь, выполняющий операцию, больше не передаётся в теле (userId из лабы 3 убран) —
 * он берётся из аутентификации, поэтому выполнить операцию от чужого имени нельзя.
 * start / complete / archive / approve / dismiss тела не требуют.
 */
public final class WorkflowDto {

    private WorkflowDto() {
    }

    /** submit: можно сразу передать исправленный текст перевода (тело необязательно). */
    public record SubmitRequest(String text) {
    }

    /** reject: замечание обязательно — без него автор не поймёт, что исправлять. */
    public record RejectRequest(@NotBlank String comment) {
    }

    /** resolve: можно одновременно исправить текст перевода (тело необязательно). */
    public record ResolveRequest(String translationText) {
    }

    public record RejectResponse(TranslationDto.Response translation, EditorialCommentDto.Response comment) {
    }

    public record ApproveResponse(TranslationDto.Response translation, TranslationProjectDto.Response project) {
    }

    public record ResolveResponse(EditorialCommentDto.Response comment, TranslationDto.Response translation) {
    }
}
