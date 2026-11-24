package ru.mtuci.translations.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtuci.translations.exception.ConflictException;
import ru.mtuci.translations.exception.ForbiddenException;
import ru.mtuci.translations.model.SourceSegment;
import ru.mtuci.translations.model.Translation;
import ru.mtuci.translations.model.TranslationProject;
import ru.mtuci.translations.model.TranslationStatus;
import ru.mtuci.translations.repository.TranslationRepository;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
@Transactional(readOnly = true)
public class TranslationService {

    static final String STATUS_OPERATIONS = "/submit, /approve, /reject";

    private final TranslationRepository translationRepository;
    private final Lookup lookup;
    private final Clock clock;

    public TranslationService(TranslationRepository translationRepository, Lookup lookup, Clock clock) {
        this.translationRepository = translationRepository;
        this.lookup = lookup;
        this.clock = clock;
    }

    public List<Translation> findAll() {
        return translationRepository.findAllByOrderByIdAsc();
    }

    public Translation findById(Long id) {
        return lookup.translation(id);
    }

    /** Перевод создаётся черновиком и только в запущенном проекте. Автор — тот, кто создаёт перевод. */
    @Transactional
    public Translation create(Long segmentId, String text, TranslationStatus status, Long actorId) {
        Validation.forbidDirectStatus(status, STATUS_OPERATIONS);
        SourceSegment segment = lookup.segmentRef(segmentId);
        Rules.requireInProgress(lookup.projectForUpdate(segment.getProject().getId()));
        Translation translation = new Translation();
        translation.setSegment(segment);
        translation.setAuthor(lookup.userRef(actorId));
        translation.setText(text.trim());
        translation.setStatus(TranslationStatus.DRAFT);
        Instant now = Instant.now(clock);
        translation.setCreatedAt(now);
        translation.setUpdatedAt(now);
        return translationRepository.saveAndFlush(translation);
    }

    /** Свой перевод правит только автор. Сменить автора нельзя — перевод всегда принадлежит тому, кто его написал. */
    @Transactional
    public Translation update(Long id, Long segmentId, String text, TranslationStatus status, Long actorId) {
        Validation.forbidDirectStatus(status, STATUS_OPERATIONS);
        Translation translation = lookup.translation(id);
        TranslationProject project = lookup.projectForUpdate(translation.getSegment().getProject().getId());
        if (!translation.getAuthor().getId().equals(actorId)) {
            throw new ForbiddenException("Изменять перевод может только его автор");
        }
        Rules.requireInProgress(project);

        if (text != null) {
            Validation.requireNotBlank(text, "text");
            if (translation.getStatus() != TranslationStatus.DRAFT && translation.getStatus() != TranslationStatus.REJECTED) {
                throw new ConflictException("Текст перевода в статусе " + translation.getStatus()
                        + " менять нельзя (только DRAFT или REJECTED)");
            }
            translation.setText(text.trim());
        }
        if (segmentId != null && !segmentId.equals(translation.getSegment().getId())) {
            requireDraft(translation, "segmentId");
            SourceSegment target = lookup.segmentRef(segmentId);
            if (!target.getProject().getId().equals(project.getId())) {
                throw new ConflictException("Перевод можно перенести только на сегмент того же проекта");
            }
            translation.setSegment(target);
        }
        translation.setUpdatedAt(Instant.now(clock));
        return translationRepository.saveAndFlush(translation);
    }

    /** Замечания к переводу удаляются каскадно на уровне БД. */
    @Transactional
    public void delete(Long id, Long actorId) {
        Translation translation = lookup.translation(id);
        TranslationProject project = lookup.projectForUpdate(translation.getSegment().getProject().getId());
        // удалить перевод может автор или владелец проекта (например, убрать лишний черновик)
        if (!translation.getAuthor().getId().equals(actorId) && !Rules.isOwner(project, actorId)) {
            throw new ForbiddenException("Удалить перевод может только его автор или владелец проекта");
        }
        Rules.requireContentEditable(project);
        translationRepository.delete(translation);
    }

    private void requireDraft(Translation translation, String field) {
        if (translation.getStatus() != TranslationStatus.DRAFT) {
            throw new ConflictException(field + " можно менять только у перевода в статусе DRAFT");
        }
    }
}
