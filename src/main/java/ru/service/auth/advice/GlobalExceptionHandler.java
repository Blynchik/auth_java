package ru.service.auth.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.LazyInitializationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import ru.service.auth.dto.ExceptionInfo;
import ru.service.auth.dto.ExceptionResponse;
import ru.service.auth.util.exception.BindingValidationException;

import java.util.ArrayList;
import java.util.List;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private final ObjectMapper objectMapper;

    @Autowired
    public GlobalExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(Exception e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(LazyInitializationException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(BindingValidationException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e.getBindingResult()));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(ValidationException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(BadCredentialsException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler
    private ResponseEntity<ExceptionResponse> handleException(InternalAuthenticationServiceException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(EntityNotFoundException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(JwtException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(HttpMessageNotReadableException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(IllegalArgumentException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(HandlerMethodValidationException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(NoResourceFoundException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler
    ResponseEntity<ExceptionResponse> handleException(IllegalStateException e) {
        logException(e);
        ExceptionResponse response = new ExceptionResponse(getExceptionInfoList(e));
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Метод преобразует все исключение в список с одним элементом ExceptionInfo
     */
    private List<ExceptionInfo> getExceptionInfoList(Exception e) {
        return List.of(new ExceptionInfo(e.getClass().getSimpleName(), "", e.getMessage()));
    }

    /**
     * Метод преобразует все ошибки BindingResult в список ExceptionInfo
     */
    private List<ExceptionInfo> getExceptionInfoList(BindingResult bindingResult) {
        List<ExceptionInfo> errorMessages = new ArrayList<>();
        for (ObjectError error : bindingResult.getAllErrors()) {
            String fieldName = "";
            String defaultMessage = error.getDefaultMessage();
            // Если ошибка связана с конкретным полем
            if (error instanceof FieldError fieldError) {
                fieldName = fieldError.getField();
                defaultMessage = fieldError.getDefaultMessage();
            }
            // Формируем сообщение об ошибке
            errorMessages.add(new ExceptionInfo(
                    BindingValidationException.class.getSimpleName(),
                    fieldName,
                    defaultMessage != null ? defaultMessage : ""));
        }
        return errorMessages;
    }

    private void logException(Exception e) {
        log.error("""
                exception: {}, message: {}
                """, e.getClass().getSimpleName(), e.getMessage());
        e.printStackTrace();
    }
}
