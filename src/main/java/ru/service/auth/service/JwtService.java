package ru.service.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ru.service.auth.config.security.JwtProperties;
import ru.service.auth.model.appUser.AuthUser;
import ru.service.auth.util.tool.TokenType;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

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

    public String generateRefreshToken(UserDetails userDetails) {
        log.info("Generating {}-token for: {}", REFRESH, userDetails.getUsername());
        return generateToken(userDetails.getUsername(),
                new Date(System.currentTimeMillis() + jwtProperties.getRefreshExpiration()),
                refreshKey,
                null);
    }

    public String generateAccessToken(UserDetails userDetails) {
        log.info("Generating {}-token for: {}", ACCESS, userDetails.getUsername());
        List<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return generateToken(userDetails.getUsername(),
                new Date(System.currentTimeMillis() + jwtProperties.getAccessExpiration()),
                accessKey,
                authorities);
    }

    private String generateToken(String login,
                                 Date expirationDate,
                                 SecretKey key,
                                 List<String> authorities) {
        var jwtBuilder = Jwts.builder()
                .subject(login)
                .issuedAt(new Date())
                .expiration(expirationDate)
                .signWith(key);
        if (authorities != null && !authorities.isEmpty()) {
            jwtBuilder.claim("authorities", authorities);
        }
        return jwtBuilder.compact();
    }

    public void verifyToken(String token, AuthUser authUser, TokenType tokenType) {
        log.info("Verifying expiration, login and change-date for {}-token", tokenType.name());
        Claims claims = extractClaims(token, tokenType);
        String extractedEmail = claims.getSubject();
        Date issuedAt = claims.getIssuedAt();
        if (claims.getExpiration().before(new Date())) {
            throw new JwtException("Token expired");
        }
        if (!extractedEmail.equals(authUser.getUsername())) {
            throw new JwtException("Invalid token");
        }
        if (issuedAt.before(authUser.getUser().getChangedAt())) {
            throw new JwtException("Invalid token. Please, login");
        }
    }
}