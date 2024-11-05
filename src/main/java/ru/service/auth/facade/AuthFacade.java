package ru.service.auth.facade;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import ru.service.auth.dto.*;
import ru.service.auth.model.appUser.AppUser;
import ru.service.auth.model.appUser.AuthUser;
import ru.service.auth.service.AppUserService;
import ru.service.auth.service.JwtService;
import ru.service.auth.validator.AppUserValidator;

import static ru.service.auth.util.tool.TokenType.ACCESS;
import static ru.service.auth.util.tool.TokenType.REFRESH;

@Service
@Slf4j
public class AuthFacade {

    private final AppUserValidator appUserValidator;
    private final AppUserService appUserService;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;

    @Autowired
    public AuthFacade(AppUserValidator appUserValidator,
                      AppUserService appUserService,
                      AuthenticationManager authManager,
                      JwtService jwtService) {
        this.appUserValidator = appUserValidator;
        this.appUserService = appUserService;
        this.authManager = authManager;
        this.jwtService = jwtService;
    }

    public AccessTokenResponse getAccessToken(AccessTokenRequest accessTokenRequest) {
        log.info("Starting to issue the token");
        String login = jwtService.extractClaims(accessTokenRequest.getRefreshToken(), REFRESH).getSubject();
        AuthUser authUser = appUserService.loadUserByUsername(login);
        jwtService.verifyToken(accessTokenRequest.getRefreshToken(), authUser, REFRESH);
        String accessToken = jwtService.generateAccessToken(authUser);
        return new AccessTokenResponse(accessToken);
    }

    public AuthResponse login(AppUserRequest userDto) {
        log.info("Starting user authentication: {}", userDto.getLogin());
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userDto.getLogin(),
                        userDto.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
        String accessToken = jwtService.generateAccessToken(authUser);
        String refreshToken = jwtService.generateRefreshToken(authUser);
        return new AuthResponse(accessToken, refreshToken);
    }

    public AppUserResponse registration(AppUserRequest userDto, BindingResult bindingResult) {
        log.info("Starting the creation of a new user: {}", userDto.getLogin());
        appUserValidator.validate(userDto, bindingResult);
        AppUser userToSave = new AppUser(userDto);
        AppUser savedUser = appUserService.create(userToSave);
        return new AppUserResponse(savedUser);
    }
}
