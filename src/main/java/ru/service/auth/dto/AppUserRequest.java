package ru.service.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppUserRequest {

    @Pattern(regexp = "^[a-zA-Z0-9_@.-]+$",
            message = "An email address can only consist of " +
                    "lowercase Latin letters, numbers, and special characters (_@.-)")
    @Size(min = 4, max = 255, message = "The login must consist of at least 4 characters")
    @NotBlank(message = "The login must consist of at least 4 characters")
    @Email(message = "Enter your email address")
    private String login;

    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
            message = "The password must consist of letters of the Latin alphabet in upper and lower case, " +
                    "numbers, as well as special characters (@, $, !, %, *, ?, &)")
    @Size(min = 8, max = 255, message = "The password must consist of at least 8 characters")
    @NotBlank(message = "The password must consist of at least 8 characters")
    private String password;
}
