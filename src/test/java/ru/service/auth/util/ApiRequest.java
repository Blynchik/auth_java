package ru.service.auth.util;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class ApiRequest {

    public static ResultActions loginCustomUser(MockMvc mockMvc, String userDtoAsString) throws Exception {
        RequestBuilder request = MockMvcRequestBuilders
                .post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(userDtoAsString);
        return mockMvc.perform(request);
    }

    public static ResultActions getAccessTokenForCustomUser(MockMvc mockMvc, String accessTokenRequestAsString) throws Exception {
        RequestBuilder request = MockMvcRequestBuilders
                .post("/api/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(accessTokenRequestAsString);

        return mockMvc.perform(request);
    }

    public static ResultActions registrationCustomUser(MockMvc mockMvc, String requestAsString) throws Exception {
        RequestBuilder userRequest = MockMvcRequestBuilders
                .post("/api/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestAsString);
        return mockMvc.perform(userRequest);
    }
}
