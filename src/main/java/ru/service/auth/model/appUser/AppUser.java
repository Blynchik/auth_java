package ru.service.auth.model.appUser;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import ru.service.auth.dto.AppUserRequest;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "app_user",
        indexes = {
                @Index(name = "idx_login", columnList = "login"),
                @Index(name = "idx_id", columnList = "id")})
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppUser {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "login", unique = true)
    @Email
    @Size(min = 4, max = 255)
    @NotBlank
    private String login;

    @Column(name = "password", nullable = false)
    @Size(min = 8, max = 255)
    @NotBlank
    private String password;

    @Column(name = "registered_at")
    @Temporal(TemporalType.TIMESTAMP)
    private Date registeredAt;

    @Column(name = "changed_at")
    @Temporal(TemporalType.TIMESTAMP)
    private Date changedAt;

    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "role",
            joinColumns = @JoinColumn(name = "app_user_id"),
            uniqueConstraints = @UniqueConstraint(columnNames = {"app_user_id", "role"}, name = "uc_user_role"))
    @Column(name = "role")
    @ElementCollection(fetch = FetchType.EAGER)
    @NotNull
    private Set<Role> roles;

    public AppUser(AppUserRequest appUserRequest) {
        this.login = appUserRequest.getLogin();
        this.password = appUserRequest.getPassword();
        this.registeredAt = new Date();
        this.changedAt = new Date();
        this.roles = new HashSet<>();
    }

    public AppUser(String login, String password) {
        this.login = login;
        this.password = password;
        this.registeredAt = new Date();
        this.changedAt = new Date();
        this.roles = new HashSet<>();
    }
}

