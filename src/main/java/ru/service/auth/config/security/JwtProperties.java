package ru.service.auth.config.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Component
@ConfigurationProperties("jwt")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtProperties {

    private String accessKey;
    private String refreshKey;
    private Long accessExpiration;
    private Long refreshExpiration;
}
