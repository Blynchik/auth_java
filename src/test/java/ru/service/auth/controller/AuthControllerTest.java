package ru.service.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Description;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import ru.service.auth.config.security.JwtProperties;
import ru.service.auth.dto.AccessTokenRequest;
import ru.service.auth.dto.AccessTokenResponse;
import ru.service.auth.dto.AppUserRequest;
import ru.service.auth.dto.AuthResponse;
import ru.service.auth.model.appUser.AuthUser;
import ru.service.auth.model.appUser.Role;
import ru.service.auth.service.AppUserService;
import ru.service.auth.service.JwtService;

import java.util.List;
import java.util.Random;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static ru.service.auth.util.ApiRequest.*;
import static ru.service.auth.util.ObjectFactory.convertJsonToObject;
import static ru.service.auth.util.ObjectFactory.getAppUserRequest1;
import static ru.service.auth.util.tool.TokenType.ACCESS;
import static ru.service.auth.util.tool.TokenType.REFRESH;

@SpringBootTest
@Transactional
@AutoConfigureMockMvc(printOnlyOnFailure = false)
public class AuthControllerTest {

    private final JwtProperties jwtProperties;
    private final AppUserService appUserService;
    private final JwtService jwtService;
    private final MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private Random random;

    @Autowired
    private AuthControllerTest(MockMvc mockMvc,
                               JwtProperties jwtProperties,
                               AppUserService appUserService,
                               JwtService jwtService) {
        this.mockMvc = mockMvc;
        this.jwtProperties = jwtProperties;
        this.appUserService = appUserService;
        this.jwtService = jwtService;
        this.objectMapper = new ObjectMapper();
        this.random = new Random();
    }

    @Nested
    @DisplayName(value = "Тесты на создание пользователя")
    class RegistrationTest {

        private AppUserRequest userDto;
        private String userAsString;

        @BeforeEach
        void setUp() throws Exception {
            this.userDto = getAppUserRequest1();
            this.userAsString = objectMapper.writeValueAsString(userDto);
        }

        @Test
        @Description(value = "Тест на успешность регистрации нового пользователя")
        void success_registration() throws Exception {
            //when
            registrationCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isCreated())
                    .andExpect(
                            jsonPath("$.login").value(userDto.getLogin()))
                    .andExpect(
                            jsonPath("$.roles[0]").value("USER"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "        "})
        @Description(value = "Тест на регистрацию пустого тела")
        void emptyBody_registration(String body) throws Exception {
            //when
            registrationCustomUser(mockMvc, body)
                    //then
                    .andExpect(
                            status().isBadRequest());
        }

        @Test
        @Description(value = "Тест на проверку не латинских букв в логине.")
        void notOnlyLatinLettersLogin_registration() throws Exception {
            //given
            this.userDto.setLogin("LoginЯй123_.-@mail.ru");
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BindingValidationException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].field").value("login"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("An email address can only consist of lowercase Latin letters, numbers, and special characters (_@.-)"));
        }

        @Test
        @Description(value = "Тест на проверку валидности короткого логина")
        void shortLogin_registration() throws Exception {
            //given
            this.userDto.setLogin("@.r");
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'login' " +
                                    "&& @.descr == 'The login must consist of at least 4 characters')]")
                                    .exists());
        }

        @Test
        @Description(value = "Тест на проверку валидности длинного логина")
        void longLogin_registration() throws Exception {
            //given
            StringBuilder login = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                login.append(Character.toString('A' + random.nextInt(26)));
            }
            this.userDto.setLogin(login.toString());
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'login' " +
                                    "&& @.descr == 'The login must consist of at least 4 characters')]")
                                    .exists());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "        "})
        @Description(value = "Тест на пустой логин")
        void emptyBlankLogin_registration(String login) throws Exception {
            //given
            this.userDto.setLogin(login);
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'login' " +
                                    "&& @.descr == 'The login must consist of at least 4 characters')]")
                                    .exists());
        }

        @Test
        @Description(value = "Тест на проверку того, что логин - это электронная почта")
        void loginAsEmail_registration() throws Exception {
            //given
            this.userDto.setLogin("biba");
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BindingValidationException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].field").value("login"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("Enter your email address"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"qwerty1234!", "QWERTY1234!", "12345678!", "Qйцу1234!._", "Qwerty1234"})
        @Description(value = "Тест на невалидные пароли")
        void notValidPassword_registration(String password) throws Exception {
            //given
            this.userDto.setPassword(password);
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BindingValidationException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].field").value("password"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("The password must consist of letters of the Latin alphabet in upper and lower case, numbers, as well as special characters (@, $, !, %, *, ?, &)"));
        }

        @Test
        @Description(value = "Тест на короткий пароль")
        void shortPassword_registration() throws Exception {
            //given
            this.userDto.setPassword("Qwert1!");
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BindingValidationException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].field").value("password"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("The password must consist of at least 8 characters"));
        }

        @Test
        @Description(value = "Тест на длинный пароль")
        void longPassword_registration() throws Exception {
            //given
            StringBuilder password = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                password.append(Character.toString('A' + random.nextInt(26)));
            }
            this.userDto.setPassword(password.toString());
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'password' " +
                                    "&& @.descr == 'The password must consist of at least 8 characters')]")
                                    .exists());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "        "})
        @Description(value = "Тест на пустой пароль")
        void emptyBlankPassword_registration(String login) throws Exception {
            //given
            this.userDto.setPassword(login);
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'password' " +
                                    "&& @.descr == 'The password must consist of at least 8 characters')]")
                                    .exists());
        }

        @Test
        @Description(value = "Тест на уникальность логина")
        void uniqueLogin_registration() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            registrationCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BindingValidationException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].field").value("login"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value(String.format("The login %s is occupied", userDto.getLogin())));
        }

        @Test
        @Description(value = "Тест на null логин")
        void nullStringLogin_registration() throws Exception {
            //given
            String login = "null";
            this.userDto.setLogin(login);
            //when
            registrationCustomUser(mockMvc, objectMapper.writeValueAsString(userDto))
                    //then
                    .andExpect(
                            status().isBadRequest())
                    .andExpect(
                            jsonPath(String.format("$.exceptions[?(@.exception == 'BindingValidationException' " +
                                    "&& @.field == 'login' " +
                                    "&& @.descr == 'Enter your email address')]", login))
                                    .exists());
        }
    }

    @Nested
    @DisplayName(value = "Тесты на аутентификацию")
    class LoginTest {

        private AppUserRequest userDto;
        private String userAsString;

        @BeforeEach
        void setUp() throws Exception {
            this.userDto = getAppUserRequest1();
            this.userAsString = objectMapper.writeValueAsString(userDto);
        }

        @Test
        @Description(value = "Тест на успешность аутентификации")
        void success_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //без ожидания токены иногда формируются в то же время, что и пользователь, что затем приводит к ошибке верификации токена
            Thread.sleep(1000);
            //when
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isOk())
                    .andExpect(
                            jsonPath("$.accessToken").value(notNullValue()))
                    .andExpect(
                            jsonPath("$.refreshToken").value(notNullValue()))
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
            jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
            List<String> authorities = jwtService.extractClaims(authResponse.getAccessToken(), ACCESS).get("authorities", List.class);
            assertNull(jwtService.extractClaims(authResponse.getRefreshToken(), REFRESH).get("authorities"));
            assertNotNull(jwtService.extractClaims(authResponse.getAccessToken(), ACCESS).get("userId", Long.class));
            assertNotNull(jwtService.extractClaims(authResponse.getRefreshToken(), REFRESH).get("userId", Long.class));
            assertEquals(1, authorities.size());
            assertEquals(Role.USER.getAuthority(), authorities.get(0));
        }

        @Test
        @Description(value = "Тест на успешность аутентификации, если подпись была изменена")
        void changedSignature_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isOk())
                    .andExpect(
                            jsonPath("$.accessToken").value(notNullValue()))
                    .andExpect(
                            jsonPath("$.refreshToken").value(notNullValue()))
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            assertEquals("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken().subSequence(0, authResponse.getAccessToken().length() - 2) + "A", authUser, ACCESS);
                            }).getMessage());
            assertEquals("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken().subSequence(0, authResponse.getAccessToken().length() - 2) + "A", authUser, ACCESS);
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на успешность аутентификации, если подпись не соответствует access-токену")
        void signatureGeneratedWithWrongAccessKey_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isOk())
                    .andExpect(
                            jsonPath("$.accessToken").value(notNullValue()))
                    .andExpect(
                            jsonPath("$.refreshToken").value(notNullValue()))
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            assertEquals("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                    assertThrows(SignatureException.class,
                            () -> {
                                Jwts.parser()
                                        .verifyWith(Keys.hmacShaKeyFor((jwtProperties.getAccessKey().subSequence(0, jwtProperties.getAccessKey().length() - 2) + "A").getBytes()))
                                        .build()
                                        .parseSignedClaims(authResponse.getAccessToken())
                                        .getPayload();
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на успешность аутентификации, если подпись не соответствует refresh-токену")
        void signatureGeneratedWithWrongRefreshKey_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isOk())
                    .andExpect(
                            jsonPath("$.accessToken").value(notNullValue()))
                    .andExpect(
                            jsonPath("$.refreshToken").value(notNullValue()))
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            assertEquals("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                    assertThrows(SignatureException.class,
                            () -> {
                                Jwts.parser()
                                        .verifyWith(Keys.hmacShaKeyFor((jwtProperties.getRefreshKey().subSequence(0, jwtProperties.getRefreshKey().length() - 2) + "A").getBytes()))
                                        .build()
                                        .parseSignedClaims(authResponse.getRefreshToken())
                                        .getPayload();
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на время валидности токенов")
        void expirationDate_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    //then
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            Thread.sleep(jwtProperties.getAccessExpiration());
            assertTrue(
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
                            }).getMessage()
                            .contains("JWT expired"));
            Thread.sleep(jwtProperties.getRefreshExpiration() - jwtProperties.getAccessExpiration());
            assertTrue(
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
                            }).getMessage()
                            .contains("JWT expired"));
        }

        @Test
        @Description(value = "Тест на валидность токенов после изменения логина пользователя")
        void tokenValidityAfterChangeLogin_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            //when
            appUserService.changeLogin(userDto.getLogin(), "boba@mail.ru");
            //then
            AuthUser authUser = appUserService.loadUserByUsername("boba@mail.ru");
            assertEquals("Invalid token",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
                            }).getMessage());
            assertEquals("Invalid token",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на валидность токенов после изменения пароля пользователя")
        void tokenValidityAfterChangePassword_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            //when
            appUserService.changePassword(userDto.getLogin(), "QazWsx1234!");
            //then
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
                            }).getMessage());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на валидность токенов после добавления прав администратора")
        void tokenValidityAfterAddAuthorities_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            //when
            appUserService.addAdminRights(userDto.getLogin());
            //then
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
                            }).getMessage());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на валидность токенов после удаления прав администратора")
        void tokenValidityAfterRemoveAuthorities_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            //when
            appUserService.removeAdminRights(userDto.getLogin());
            //then
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getAccessToken(), authUser, ACCESS);
                            }).getMessage());
            assertEquals("Invalid token. Please, login",
                    assertThrows(JwtException.class,
                            () -> {
                                jwtService.verifyToken(authResponse.getRefreshToken(), authUser, REFRESH);
                            }).getMessage());
        }

        @Test
        @Description(value = "Тест на валидность токенов после удаления пользователя")
        void tokenValidityAfterRemoveUser_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            String responseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn().getResponse().getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, responseAsString, AuthResponse.class);
            //when
            appUserService.delete(appUserService.getByLogin(userDto.getLogin()));
            //then
            assertEquals("Bad credentials",
                    assertThrows(BadCredentialsException.class,
                            () -> {
                                appUserService.loadUserByUsername(userDto.getLogin());
                            }).getMessage());
            assertEquals("Bad credentials",
                    assertThrows(BadCredentialsException.class,
                            () -> {
                                appUserService.loadUserByUsername(userDto.getLogin());
                            }).getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "        "})
        @Description(value = "Тест на аутентификацию с пустым телом")
        void emptyBody_login(String body) throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //when
            loginCustomUser(mockMvc, body)
                    //then
                    .andExpect(
                            status().isBadRequest());
        }

        @Test
        @Description(value = "Тест на аутентификацию без учетной записи")
        void noUser_login() throws Exception {
            //when
            loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isForbidden())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("InternalAuthenticationServiceException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("Bad credentials"));
        }

        @Test
        @Description(value = "Тест на аутентификацию с неверным логином, если такого пользователя нет")
        void wrongLoginUserNotExist_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            this.userDto.setLogin("WrongLogin");
            String userAsString = objectMapper.writeValueAsString(userDto);
            //when
            loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isForbidden())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("InternalAuthenticationServiceException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("Bad credentials"));
        }

        @Test
        @Description(value = "Тест на аутентификацию с неверным паролем")
        void wrongLoginUserExist_login() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            this.userDto.setPassword("Qwerty987654!");
            String userAsString = objectMapper.writeValueAsString(userDto);
            //when
            loginCustomUser(mockMvc, userAsString)
                    //then
                    .andExpect(
                            status().isForbidden())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("BadCredentialsException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("Bad credentials"));
        }
    }

    @Nested
    @DisplayName(value = "Тесты на получение access-токена")
    class GetAccessTokenTest {

        private AppUserRequest userDto;
        private String userAsString;

        @BeforeEach
        void setUp() throws Exception {
            this.userDto = getAppUserRequest1();
            this.userAsString = objectMapper.writeValueAsString(userDto);
        }

        @Test
        @Description(value = "Тест на успешность получения access-токена")
        void success_getAccessToken() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //без ожидания токены иногда формируются в то же время, что и пользователь, что затем приводит к ошибке верификации токена
            Thread.sleep(1000);
            String authResponseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn()
                    .getResponse()
                    .getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, authResponseAsString, AuthResponse.class);
            //when
            String accessTokenResponseAsString = getAccessTokenForCustomUser(mockMvc, objectMapper.writeValueAsString(new AccessTokenRequest(authResponse.getRefreshToken())))
                    .andExpect(
                            status().isOk())
                    .andExpect(
                            jsonPath("$.accessToken").value(notNullValue()))
                    .andReturn().getResponse().getContentAsString();
            AccessTokenResponse accessTokenResponse = convertJsonToObject(objectMapper, accessTokenResponseAsString, AccessTokenResponse.class);
            AuthUser authUser = appUserService.loadUserByUsername(userDto.getLogin());
            jwtService.verifyToken(accessTokenResponse.getAccessToken(), authUser, ACCESS);
            List<String> authorities = jwtService.extractClaims(authResponse.getAccessToken(), ACCESS).get("authorities", List.class);
            assertEquals(1, authorities.size());
            assertEquals(Role.USER.getAuthority(), authorities.get(0));
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "        "})
        @Description(value = "Тест на получение access-токена с пустым телом")
        void emptyBody_getAccessToken(String body) throws Exception {
            //given
            //без ожидания токены иногда формируются в то же время, что и пользователь, что затем приводит к ошибке верификации токена
            Thread.sleep(1000);
            loginCustomUser(mockMvc, userAsString);
            getAccessTokenForCustomUser(mockMvc, body)
                    .andExpect(
                            status().isBadRequest());
        }

        @Test
        @Description(value = "Тест на получение access-токена при отправке access-токена вместо refresh")
        void accessTokenInsteadRefresh_getAccessToken() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //без ожидания токены иногда формируются в то же время, что и пользователь, что затем приводит к ошибке верификации токена
            Thread.sleep(1000);
            String authResponseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn()
                    .getResponse()
                    .getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, authResponseAsString, AuthResponse.class);
            //when
            getAccessTokenForCustomUser(mockMvc, objectMapper.writeValueAsString(new AccessTokenRequest(authResponse.getAccessToken())))
                    .andExpect(
                            status().isForbidden())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("JwtException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted."));
        }

        @Test
        @Description(value = "Тест на получение access-токена, если refresh-токен просрочен")
        void refreshTokenExpired_getAccessToken() throws Exception {
            //given
            registrationCustomUser(mockMvc, userAsString);
            //без ожидания токены иногда формируются в то же время, что и пользователь, что затем приводит к ошибке верификации токена
            Thread.sleep(1000);
            String authResponseAsString = loginCustomUser(mockMvc, userAsString)
                    .andReturn()
                    .getResponse()
                    .getContentAsString();
            AuthResponse authResponse = convertJsonToObject(objectMapper, authResponseAsString, AuthResponse.class);
            Thread.sleep(jwtProperties.getRefreshExpiration());
            //when
            getAccessTokenForCustomUser(mockMvc, objectMapper.writeValueAsString(new AccessTokenRequest(authResponse.getRefreshToken())))
                    .andExpect(
                            status().isForbidden())
                    .andExpect(
                            jsonPath("$.exceptions[0].exception").value("JwtException"))
                    .andExpect(
                            jsonPath("$.exceptions[0].descr").value(containsString("JWT expired")));
        }
    }
}
