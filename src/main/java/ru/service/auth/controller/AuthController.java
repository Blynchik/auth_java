package ru.service.auth.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.service.auth.dto.*;
import ru.service.auth.facade.AuthFacade;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    //todo
    // добавить изменение логина только с помощью refresh токена
    // изменение пароля только с помощью refresh токена
    // добавление прав админа
    // удаление прав админа
    // разлогирование
    // или сделать отдельный сервис для этого, кроме разлогирования
    // Передачу refresh-токена осуществить через HttpOnly cookies

    private final AuthFacade authFacade;

    @Autowired
    public AuthController(AuthFacade authFacade) {
        this.authFacade = authFacade;
    }

    @PostMapping("/token")
    public ResponseEntity<AccessTokenResponse> getAccessToken(@RequestBody AccessTokenRequest accessTokenRequest) {
        log.info("Request to POST /api/auth/token");
        return ResponseEntity.ok(authFacade.getAccessToken(accessTokenRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AppUserRequest userDto) {
        log.info("Request to POST /api/auth/login from: {}", userDto.getLogin());
        return ResponseEntity.ok(authFacade.login(userDto));
    }

    @PostMapping("/registration")
    public ResponseEntity<AppUserResponse> registration(@Valid @RequestBody AppUserRequest userDto,
                                                        BindingResult bindingResult) {
        log.info("Request to POST /api/auth/registration");
        AppUserResponse responseUser = authFacade.registration(userDto, bindingResult);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseUser);
    }
}
