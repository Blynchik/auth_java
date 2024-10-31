package ru.service.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import ru.service.auth.model.appUser.AppUser;
import ru.service.auth.model.appUser.Role;

import java.util.Date;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppUserResponse {

    private Long id;
    private String login;
    private Date registeredAt;
    private Set<Role> roles;

    public AppUserResponse(AppUser appUser) {
        this.id = appUser.getId();
        this.login = appUser.getLogin();
        this.registeredAt = appUser.getRegisteredAt();
        this.roles = appUser.getRoles();
    }
}
