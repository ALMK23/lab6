package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.TranslationDto;
import ru.mtuci.translations.dto.WorkflowDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.ReviewWorkflowService;
import ru.mtuci.translations.service.TranslationService;

import java.util.List;

/**
 * Переводы. Писать и отправлять переводы — TRANSLATIONS_WRITE (переводчик, редактор),
 * утверждать и отклонять — TRANSLATIONS_REVIEW (редактор, и только в своём проекте и не свой перевод).
 */
@RestController
@RequestMapping("/api/translations")
@PreAuthorize("isAuthenticated()")
public class TranslationController {

    private final TranslationService service;
    private final ReviewWorkflowService workflow;
    private final ResponseMapper mapper;

    public TranslationController(TranslationService service, ReviewWorkflowService workflow, ResponseMapper mapper) {
        this.service = service;
        this.workflow = workflow;
        this.mapper = mapper;
    }

    @GetMapping
    public List<TranslationDto.Response> getAll() {
        return service.findAll().stream().map(mapper::toResponse).toList();
    }

    @GetMapping("/{id}")
    public TranslationDto.Response getById(@PathVariable Long id) {
        return mapper.toResponse(service.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('TRANSLATIONS_WRITE')")
    public TranslationDto.Response create(@Valid @RequestBody TranslationDto.CreateRequest request,
                                          @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.create(request.segmentId(), request.text(), request.status(), me.getId()));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('TRANSLATIONS_WRITE')")
    public TranslationDto.Response update(@PathVariable Long id,
                                          @Valid @RequestBody TranslationDto.PatchRequest request,
                                          @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.update(id, request.segmentId(), request.text(), request.status(), me.getId()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('TRANSLATIONS_WRITE')")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        service.delete(id, me.getId());
    }

    // --- бизнес-операции ---

    @PostMapping("/{id}/submit")
    @PreAuthorize("hasAuthority('TRANSLATIONS_WRITE')")
    public TranslationDto.Response submit(@PathVariable Long id,
                                          @RequestBody(required = false) WorkflowDto.SubmitRequest request,
                                          @AuthenticationPrincipal SecurityUser me) {
        String text = request != null ? request.text() : null;
        return mapper.toResponse(workflow.submit(id, me.getId(), text));
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public WorkflowDto.RejectResponse reject(@PathVariable Long id, @Valid @RequestBody WorkflowDto.RejectRequest request,
                                             @AuthenticationPrincipal SecurityUser me) {
        ReviewWorkflowService.RejectResult result = workflow.reject(id, me.getId(), request.comment());
        return new WorkflowDto.RejectResponse(mapper.toResponse(result.translation()), mapper.toResponse(result.comment()));
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public WorkflowDto.ApproveResponse approve(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        ReviewWorkflowService.ApproveResult result = workflow.approve(id, me.getId());
        return new WorkflowDto.ApproveResponse(mapper.toResponse(result.translation()), mapper.toResponse(result.project()));
    }
}
