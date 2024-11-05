package ru.service.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import ru.service.auth.dto.AppUserRequest;

import java.util.List;
import java.util.Random;

public class ObjectFactory {

    public static String getRandomString(Random random, int length) {
        StringBuilder string = new StringBuilder();
        for (int i = 0; i < length; i++) {
            string.append(Character.toString('A' + random.nextInt(26)));
        }
        return string.toString();
    }

    public static <T> T convertJsonToObject(ObjectMapper objectMapper, String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, clazz);
        } catch (Exception e) {
            throw new RuntimeException("Convert error " + clazz.getSimpleName(), e);
        }
    }

    public static <T> List<T> convertJsonToList(ObjectMapper objectMapper, String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, objectMapper.getTypeFactory().constructCollectionType(List.class, clazz));
        } catch (Exception e) {
            throw new RuntimeException("Convert error " + clazz.getSimpleName() + ">", e);
        }
    }

    public static AppUserRequest getAppUserRequest2() {
        return getAppUserRequestCustom(
                "boba@mail.ru",
                "Qwerty12345!");
    }

    public static AppUserRequest getAppUserRequest1() {
        return getAppUserRequestCustom(
                "biba@yandex.ru",
                "Qwerty12345!");
    }

    public static AppUserRequest getAppUserRequestCustom(String login, String password) {
        return new AppUserRequest(login, password);
    }
}
