package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.TranslationProjectDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.ProjectWorkflowService;
import ru.mtuci.translations.service.TranslationProjectService;

import java.util.List;

/**
 * Проекты. Читать могут все вошедшие пользователи, создавать и вести — редакторы (PROJECTS_MANAGE),
 * причём менять можно только свои проекты (проверяется в сервисах).
 */
@RestController
@RequestMapping("/api/translation-projects")
@PreAuthorize("isAuthenticated()")
public class TranslationProjectController {

    private final TranslationProjectService service;
    private final ProjectWorkflowService workflow;
    private final ResponseMapper mapper;

    public TranslationProjectController(TranslationProjectService service, ProjectWorkflowService workflow,
                                        ResponseMapper mapper) {
        this.service = service;
        this.workflow = workflow;
        this.mapper = mapper;
    }

    @GetMapping
    public List<TranslationProjectDto.Response> getAll() {
        return service.findAll().stream().map(mapper::toResponse).toList();
    }

    @GetMapping("/{id}")
    public TranslationProjectDto.Response getById(@PathVariable Long id) {
        return mapper.toResponse(service.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public TranslationProjectDto.Response create(@Valid @RequestBody TranslationProjectDto.CreateRequest request,
                                                 @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.create(request.name(), request.targetLanguage(), request.status(), me.getId()));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public TranslationProjectDto.Response update(@PathVariable Long id,
                                                 @Valid @RequestBody TranslationProjectDto.PatchRequest request,
                                                 @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.update(id, request.name(), request.targetLanguage(),
                request.ownerId(), request.status(), me.getId()));
    }

    /** Удалить можно свой проект, а администратор — любой. */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE') or hasRole('ADMIN')")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        service.delete(id, me.getId());
    }

    // --- бизнес-операции (выполняет владелец проекта) ---

    @PostMapping("/{id}/start")
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public TranslationProjectDto.Response start(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(workflow.start(id, me.getId()));
    }

    @PostMapping("/{id}/complete")
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public TranslationProjectDto.Response complete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(workflow.complete(id, me.getId()));
    }

    @PostMapping("/{id}/archive")
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public TranslationProjectDto.Response archive(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(workflow.archive(id, me.getId()));
    }
}
