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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.Collections;
import java.util.Date;
@Configuration
@EnableWebSecurity
class SecurityConfig {
    private final JwtFilter jwtFilter;
    public SecurityConfig(JwtFilter jwtFilter) { this.jwtFilter=jwtFilter;}
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/login", "/swagger-ui/**", "/v3/api-docs/**", "/api/download/**", "/").permitAll().anyRequest().authenticated()).sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
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
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 3;
    public String generateToken(String username){
        return  Jwts.builder().setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)).signWith(SECRET_KEY).compact();
    }
    public String extractUsername(String token){
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody().getSubject();

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
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, token, Collections.emptyList());
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
    public String login(@RequestBody AuthRequest request){
        if ("admin".equals(request.getUsername()) && "admin".equals(request.getPassword())){
            return jwtUtil.generateToken(request.getUsername());
        }
        throw new RuntimeException("Invalid credetial");
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
public class JwtAuth {
}
