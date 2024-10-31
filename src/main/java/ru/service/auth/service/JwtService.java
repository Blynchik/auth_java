package ru.service.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.service.auth.config.security.JwtProperties;
import ru.service.auth.model.appUser.AuthUser;
import ru.service.auth.util.tool.TokenType;

import javax.crypto.SecretKey;
import java.util.Date;

import static ru.service.auth.util.tool.TokenType.ACCESS;
import static ru.service.auth.util.tool.TokenType.REFRESH;

@Service
@Slf4j
public class JwtService {

    private final JwtProperties jwtProperties;
    private SecretKey accessKey;
    private SecretKey refreshKey;

    @Autowired
    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.accessKey = Keys.hmacShaKeyFor(jwtProperties.getAccessKey().getBytes());
        this.refreshKey = Keys.hmacShaKeyFor(jwtProperties.getRefreshKey().getBytes());
    }

    public Claims extractClaims(String token, TokenType tokenType) {
        log.info("Verifying with key and extracting claims for {}-token", tokenType.name());
        SecretKey key = tokenType.equals(ACCESS) ? accessKey : refreshKey;
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            throw new JwtException(e.getMessage());
        }
        return claims;
    }

    public String generateRefreshToken(String login) {
        log.info("Generating {}-token for: {}", REFRESH, login);
        return generateToken(login,
                new Date(System.currentTimeMillis() + jwtProperties.getRefreshExpiration()),
                refreshKey);
    }

    public String generateAccessToken(String login) {
        log.info("Generating {}-token for: {}", ACCESS, login);
        return generateToken(login,
                new Date(System.currentTimeMillis() + jwtProperties.getAccessExpiration()),
                accessKey);
    }

    private String generateToken(String login,
                                 Date expirationDate,
                                 SecretKey key) {
        return Jwts.builder()
                .subject(login)
                .issuedAt(new Date())
                .expiration(expirationDate)
                .signWith(key)
                .compact();
    }

    public void verifyToken(String token, AuthUser authUser, TokenType tokenType) {
        log.info("Verifying expiration, login and change date for {}-token", tokenType.name());
        Claims claims = extractClaims(token, tokenType);
        String extractedEmail = claims.getSubject();
        if (claims.getExpiration().before(new Date())) {
            throw new JwtException("Token expired");
        }
        if (!extractedEmail.equals(authUser.getUsername())) {
            throw new JwtException("Invalid token");
        }
        if (claims.getIssuedAt().before(authUser.getUser().getChangedAt())) {
            throw new JwtException("Invalid token. Please, login");
        }
    }
}