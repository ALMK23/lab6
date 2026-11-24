package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.SourceSegmentDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.SourceSegmentService;

import java.util.List;

/** Исходные сегменты. Менять их может только редактор — владелец проекта. */
@RestController
@RequestMapping("/api/source-segments")
@PreAuthorize("isAuthenticated()")
public class SourceSegmentController {

    private final SourceSegmentService service;
    private final ResponseMapper mapper;

    public SourceSegmentController(SourceSegmentService service, ResponseMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    @GetMapping
    public List<SourceSegmentDto.Response> getAll() {
        return service.findAll().stream().map(mapper::toResponse).toList();
    }

    @GetMapping("/{id}")
    public SourceSegmentDto.Response getById(@PathVariable Long id) {
        return mapper.toResponse(service.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public SourceSegmentDto.Response create(@Valid @RequestBody SourceSegmentDto.CreateRequest request,
                                            @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.create(request.projectId(), request.sourceText(), request.position(), me.getId()));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public SourceSegmentDto.Response update(@PathVariable Long id,
                                            @Valid @RequestBody SourceSegmentDto.PatchRequest request,
                                            @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.update(id, request.projectId(), request.sourceText(),
                request.position(), me.getId()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('PROJECTS_MANAGE')")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        service.delete(id, me.getId());
    }
}
