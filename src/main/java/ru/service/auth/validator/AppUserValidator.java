package ru.service.auth.validator;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ru.service.auth.dto.AppUserRequest;
import ru.service.auth.service.AppUserService;
import ru.service.auth.util.exception.BindingValidationException;

@Component
@Slf4j
public class AppUserValidator implements Validator {

    private final AppUserService appUserService;

    @Autowired
    public AppUserValidator(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return AppUserRequest.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        AppUserRequest userDto = (AppUserRequest) target;
        log.info("Validating a new user: {}", userDto.getLogin());
        validateCreate(userDto, errors);
        if (errors.hasErrors()) {
            throw new BindingValidationException((BindingResult) errors);
        }
    }

    private void validateCreate(AppUserRequest userDto, Errors errors) {
        if (appUserService.getByLoginOptional(userDto.getLogin()).isPresent()) {
            String s = String.format("The login %s is occupied", userDto.getLogin());
            errors.rejectValue("login", "", s);
            log.info(s);
        }

        if (userDto.getLogin() == null || userDto.getLogin().equals("null")) {
            String s = String.format("Invalid login %s", "null");
            errors.rejectValue("login", "", s);
            log.info(s);
        }
    }
}
