package ru.service.auth.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class ExceptionInfo {

    private String exception;
    private String field;
    private String descr;

    public ExceptionInfo(String exception, String field, String descr) {
        this.exception = exception;
        this.field = field;
        this.descr = descr;
    }
}
