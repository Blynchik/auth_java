package ru.service.auth.util.exception;

import jakarta.validation.ValidationException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.validation.BindingResult;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
public class BindingValidationException extends ValidationException {

    private BindingResult bindingResult;
}
