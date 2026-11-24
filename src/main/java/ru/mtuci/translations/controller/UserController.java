package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.UserDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.UserService;

import java.util.List;

/**
 * Пользователи. Список, создание, смена роли, блокировка и удаление — только администратор.
 * Свою карточку пользователь может посмотреть и изменить сам.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService service;
    private final ResponseMapper mapper;

    public UserController(UserService service, ResponseMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public List<UserDto.Response> getAll() {
        return service.findAll().stream().map(mapper::toResponse).toList();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USERS_MANAGE') or #id == authentication.principal.id")
    public UserDto.Response getById(@PathVariable Long id) {
        return mapper.toResponse(service.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public UserDto.Response create(@Valid @RequestBody UserDto.CreateRequest request) {
        return mapper.toResponse(service.create(request.name(), request.email(), request.password(), request.role()));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('USERS_MANAGE') or #id == authentication.principal.id")
    public UserDto.Response update(@PathVariable Long id, @Valid @RequestBody UserDto.PatchRequest request) {
        return mapper.toResponse(service.update(id, request.name(), request.email()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        service.delete(id, me.getId());
    }

    // --- администрирование учётных записей ---

    @PatchMapping("/{id}/role")
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public UserDto.Response changeRole(@PathVariable Long id, @Valid @RequestBody UserDto.RoleRequest request,
                                       @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.changeRole(id, request.role(), me.getId()));
    }

    @PostMapping("/{id}/block")
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public UserDto.Response block(@PathVariable Long id, @AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(service.block(id, me.getId()));
    }

    @PostMapping("/{id}/unblock")
    @PreAuthorize("hasAuthority('USERS_MANAGE')")
    public UserDto.Response unblock(@PathVariable Long id) {
        return mapper.toResponse(service.unblock(id));
    }
}
