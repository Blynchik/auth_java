package ru.service.auth.model.appUser;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

@Getter
public class AuthUser extends User {

    private final AppUser user;

    public AuthUser(@NotNull AppUser user) {
        super(user.getLogin(), user.getPassword(), user.getRoles());
        this.user = user;
    }
}
