package ru.service.auth.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.service.auth.model.appUser.AppUser;
import ru.service.auth.model.appUser.AuthUser;
import ru.service.auth.model.appUser.Role;
import ru.service.auth.repo.AppUserRepo;

import java.util.Date;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
@Slf4j
public class AppUserService implements UserDetailsService {

    private final AppUserRepo appUserRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppUserService(AppUserRepo appUserRepo,
                          PasswordEncoder passwordEncoder) {
        this.appUserRepo = appUserRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public AppUser removeAdminRights(String login) {
        AppUser appUser = getByLogin(login);
        log.info(String.format("Removing administrator rights for: %s", login));
        appUser.getRoles().remove(Role.ADMIN);
        return save(appUser);
    }

    @Transactional
    public AppUser changeLogin(String login, String newLogin) {
        log.info(String.format("Changing login for: %s on %s", login, newLogin));
        AppUser appUser = getByLogin(login);
        appUser.setLogin(newLogin);
        return save(appUser);
    }

    @Transactional
    public AppUser changePassword(String login, String newPassword) {
        log.info(String.format("Changing password for: %s", login));
        AppUser appUser = getByLogin(login);
        appUser.setPassword(passwordEncoder.encode(newPassword));
        return save(appUser);
    }

    public Optional<AppUser> getByLoginOptional(String login) {
        log.info("Looking for a user: {}", login);
        return appUserRepo.findByLogin(login);
    }

    public AppUser getByLogin(String login) {
        log.info("Looking for a user: {}", login);
        return appUserRepo.findByLogin(login)
                .orElseThrow(() ->
                        new EntityNotFoundException("The user was not found"));
    }

    @Transactional
    public AppUser create(AppUser user) {
        log.info("Creating a new user: {}", user.getLogin());
        user.getRoles().add(Role.USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return save(user);
    }

    @Transactional
    public void delete(AppUser user) {
        log.info("Deleting the user: {}", user.getLogin());
        appUserRepo.deleteById(user.getId());
    }

    @Transactional
    public AppUser addAdminRights(String login) {
        AppUser appUser = getByLogin(login);
        log.info(String.format("Adding administrator rights for: %s", login));
        appUser.getRoles().add(Role.ADMIN);
        return save(appUser);
    }

    @Transactional
    public AppUser save(AppUser appUser) {
        log.info("Saving the user: {}", appUser.getLogin());
        appUser.setChangedAt(new Date());
        return appUserRepo.save(appUser);
    }

    @Override
    public AuthUser loadUserByUsername(String login) throws UsernameNotFoundException {
        log.debug("Looking for a user: {}", login);
        Optional<AppUser> optionalUser = getByLoginOptional(login);
        return new AuthUser(optionalUser.orElseThrow(
                () -> new BadCredentialsException("Invalid credentials")));
    }
}
