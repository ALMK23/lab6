package ru.mtuci.translations.service;

import ru.mtuci.translations.exception.ConflictException;
import ru.mtuci.translations.exception.ForbiddenException;
import ru.mtuci.translations.model.ProjectStatus;
import ru.mtuci.translations.model.TranslationProject;

/** Общие правила состояния проекта, которые используют и CRUD, и бизнес-операции. */
final class Rules {

    private Rules() {
    }

    /** Сегменты, переводы и замечания можно менять, только пока проект в DRAFT или IN_PROGRESS. */
    static void requireContentEditable(TranslationProject project) {
        if (!project.getStatus().isContentEditable()) {
            throw new ConflictException("Проект id=" + project.getId() + " в статусе " + project.getStatus()
                    + " — его содержимое изменять нельзя");
        }
    }

    /** Переводы и замечания работают только в запущенном проекте. */
    static void requireInProgress(TranslationProject project) {
        if (project.getStatus() != ProjectStatus.IN_PROGRESS) {
            throw new ConflictException("Проект id=" + project.getId() + " в статусе " + project.getStatus()
                    + ", а операция доступна только в статусе IN_PROGRESS");
        }
    }

    static boolean isOwner(TranslationProject project, Long userId) {
        return project.getOwner().getId().equals(userId);
    }

    /** Контекстная проверка: роль редактора даёт право менять только СВОИ проекты. */
    static void requireOwner(TranslationProject project, Long userId, String action) {
        if (!isOwner(project, userId)) {
            throw new ForbiddenException(action + " может только владелец проекта id=" + project.getId());
        }
    }
}
