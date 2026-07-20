package com.nietkali.restapi;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
@Configuration
@EnableWebSecurity
class SecurityConfig {
    private final JwtFilter jwtFilter;
    public SecurityConfig(JwtFilter jwtFilter) { this.jwtFilter=jwtFilter;}
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/login", "/api/auth/refresh", "/swagger-ui/**", "/v3/api-docs/**", "/api/download/**", "/").permitAll().anyRequest().authenticated()).sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder().username("admin").password("admin").roles("USER").build();
        return  new InMemoryUserDetailsManager(admin);
    }
}
@Component
class JwtUtil {
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long ACCESS_T_T = 1000 * 60 * 15;
    private static final long REFRESH_T_T = 1000 * 60 * 60 * 24 * 7;
    private final Map<String, String> refreshtokensStorage = new ConcurrentHashMap<>();
    public String generateAccessToken(String username){
        return  Jwts.builder().setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + ACCESS_T_T)).signWith(SECRET_KEY).compact();
    }
    public String generateRefreshToken(String username) {
        String refreshToken = Jwts.builder().setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + REFRESH_T_T)).signWith(SECRET_KEY).compact();
        refreshtokensStorage.put(refreshToken, username);
        return refreshToken;
    }
    public String extractUsername(String token){
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody().getSubject();

    }
    public boolean validaterefreshToken(String token){
        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return  refreshtokensStorage.containsKey(token);
        } catch (Exception e) {
            return false;
        }
    }
    public void invalidateRefreshToken (String token) {
        refreshtokensStorage.remove(token);
    }
}
@Component
class JwtFilter extends OncePerRequestFilter{
    private final JwtUtil jwtUtil;
    public JwtFilter(JwtUtil jwtUtil) {this.jwtUtil=jwtUtil;}
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException{
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")){
            String token = authHeader.substring(7);
            try {
                String username = jwtUtil.extractUsername(token);
                if (username!=null&&SecurityContextHolder.getContext().getAuthentication()==null){
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            } catch (Exception ignored) {}
        } chain.doFilter(request, response);
    }
}
@RestController
@RequestMapping("/api/auth")
class AuthController {
    private final JwtUtil jwtUtil;
    public AuthController(JwtUtil jwtUtil) {this.jwtUtil=jwtUtil;}
    @PostMapping("/login")
    public JwtResponse login(@RequestBody AuthRequest request){
        if ("admin".equals(request.getUsername()) && "admin".equals(request.getPassword())){
            String accessToken = jwtUtil.generateAccessToken(request.getUsername());
            String refreshToken = jwtUtil.generateRefreshToken(request.getUsername());
            return new JwtResponse(accessToken, refreshToken);
        }
        throw new RuntimeException("Invalid credetial");
    }
    @PostMapping("/refresh")
    public JwtResponse refresh (@RequestBody RefreshRequest request){
        String refreshToken = request.getRefreshToken();
        if (refreshToken != null && jwtUtil.validaterefreshToken(refreshToken)){
            String username = jwtUtil.extractUsername(refreshToken);
            String newAccessToekn = jwtUtil.generateAccessToken(username);
            String newReshtoken = jwtUtil.generateRefreshToken(username);
            jwtUtil.invalidateRefreshToken(refreshToken);
            return new JwtResponse(newAccessToekn, newReshtoken);
        } throw new RuntimeException("Invalid or Expired Refresh Token");
    }
}
class AuthRequest{
    private String username;
    private String password;
    public String getUsername(){return  username;}

    public void setUsername(String username) {
        this.username = username;
    }
    public String getPassword(){return password;}

    public void setPassword(String password) {
        this.password = password;
    }
}
class RefreshRequest{
    private String refreshToken;
    public String getRefreshToken() {return refreshToken;}
    public void setRefreshToken(String refreshToken) {this.refreshToken = refreshToken;}
}
class JwtResponse {
    private final String accessToken;
    private final String refreshToken;
    public JwtResponse(String accessToken, String refreshToken){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
public class JwtAuth {
}
