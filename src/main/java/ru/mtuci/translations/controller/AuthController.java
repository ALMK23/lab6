package ru.mtuci.translations.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import ru.mtuci.translations.dto.AuthDto;
import ru.mtuci.translations.dto.UserDto;
import ru.mtuci.translations.security.SecurityUser;
import ru.mtuci.translations.service.UserService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final ResponseMapper mapper;

    public AuthController(UserService userService, ResponseMapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    /**
     * Получение CSRF-токена (доступно без входа).
     * Вместе с ответом сервер ставит cookie XSRF-TOKEN; во всех изменяющих запросах нужно
     * отправлять эту cookie и токен из ответа в заголовке X-XSRF-TOKEN.
     */
    @GetMapping("/csrf")
    public AuthDto.CsrfResponse csrf(CsrfToken token) {
        return new AuthDto.CsrfResponse(token.getHeaderName(), token.getParameterName(), token.getToken());
    }

    /** Регистрация (доступна без входа, но с CSRF-токеном). */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserDto.Response register(@Valid @RequestBody AuthDto.RegisterRequest request) {
        return mapper.toResponse(userService.register(request.name(), request.email(), request.password()));
    }

    /** Кто я: удобно проверить, что логин и пароль подходят, и посмотреть свою роль. */
    @GetMapping("/me")
    public UserDto.Response me(@AuthenticationPrincipal SecurityUser me) {
        return mapper.toResponse(userService.findById(me.getId()));
    }

    @PostMapping("/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@AuthenticationPrincipal SecurityUser me,
                               @Valid @RequestBody AuthDto.ChangePasswordRequest request) {
        userService.changePassword(me.getId(), request.currentPassword(), request.newPassword());
    }
}
