package com.myxinh.cusc.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class TokenProvider {//create jwt token

    @Value("${secretKey}")
    private String secretKey;

    private static final String AUTHORITIES_KEY = "auth";

    public TokenProvider() {
    }


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // cấp token
    public String createToken(Authentication authentication,boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        long now = (new Date()).getTime();
        Date validity;
        if (rememberMe) {
            validity = new Date(now + System.currentTimeMillis() + 1000 * 60 * 60 * 10);
        } else {
            validity = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10);
        }
//        new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY,authorities)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256,secretKey)
                .compact();
    }

    //xác thực token
    public Boolean validateToken(String token) {
        return !isTokenExpired(token);
    }

    public Authentication getAuthentication(String token){
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(extractAllClaims(token).get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        User principal = new User(extractUsername(token),"",authorities);
        return new UsernamePasswordAuthenticationToken(principal,token,authorities);
    }

    public String resolveToken(HttpServletRequest request){// decrypt token
        String bearerToken = request.getHeader("Authorization");
        if(!Objects.isNull(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }

}
