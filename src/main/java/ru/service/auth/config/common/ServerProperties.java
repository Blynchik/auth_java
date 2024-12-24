package ru.service.auth.config.common;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("server")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ServerProperties {

    private String port;
    private String address;
    private String name;
}
