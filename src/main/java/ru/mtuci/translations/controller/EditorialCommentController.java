package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.EditorialCommentDto;
import ru.mtuci.translations.dto.WorkflowDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.EditorialCommentService;
import ru.mtuci.translations.service.ReviewWorkflowService;

import java.util.List;

/** Замечания оставляет и снимает редактор (TRANSLATIONS_REVIEW), устраняет — автор перевода (TRANSLATIONS_WRITE). */
@RestController
@RequestMapping("/api/editorial-comments")
@PreAuthorize("isAuthenticated()")
public class EditorialCommentController {

    private final EditorialCommentService service;
    private final ReviewWorkflowService workflow;
    private final ResponseMapper mapper;

    public EditorialCommentController(EditorialCommentService service, ReviewWorkflowService workflow,
                                      ResponseMapper mapper) {
        this.service = service;
        this.workflow = workflow;
        this.mapper = mapper;
    }

    @GetMapping
    public List<EditorialCommentDto.Response> getAll() {
        return service.findAll().stream().map(mapper::toResponse).toList();
    }

    @GetMapping("/{id}")
    public EditorialCommentDto.Response getById(@PathVariable Long id) {
        return mapper.toResponse(service.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public EditorialCommentDto.Response create(@Valid @RequestBody EditorialCommentDto.CreateRequest request,
                                               @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.create(request.translationId(), request.text(), request.status(), me.getId()));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public EditorialCommentDto.Response update(@PathVariable Long id,
                                               @Valid @RequestBody EditorialCommentDto.PatchRequest request,
                                               @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.update(id, request.translationId(), request.text(), request.status(), me.getId()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        service.delete(id, me.getId());
    }

    // --- бизнес-операции ---

    @PostMapping("/{id}/resolve")
    @PreAuthorize("hasAuthority('TRANSLATIONS_WRITE')")
    public WorkflowDto.ResolveResponse resolve(@PathVariable Long id,
                                               @RequestBody(required = false) WorkflowDto.ResolveRequest request,
                                               @AuthenticationPrincipal SecurityUser me) {
        String text = request != null ? request.translationText() : null;
        ReviewWorkflowService.ResolveResult result = workflow.resolve(id, me.getId(), text);
        return new WorkflowDto.ResolveResponse(mapper.toResponse(result.comment()), mapper.toResponse(result.translation()));
    }

    @PostMapping("/{id}/dismiss")
    @PreAuthorize("hasAuthority('TRANSLATIONS_REVIEW')")
    public EditorialCommentDto.Response dismiss(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(workflow.dismiss(id, me.getId()));
    }
}
