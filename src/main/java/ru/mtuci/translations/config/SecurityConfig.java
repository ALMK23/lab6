package ru.mtuci.translations.config;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import ru.mtuci.translations.security.RestAccessDeniedHandler;
import ru.mtuci.translations.security.AccessTokenFilter;
import ru.mtuci.translations.security.AppUserDetailsService;
import ru.mtuci.translations.security.JwtService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import ru.mtuci.translations.security.RestAuthenticationEntryPoint;

/**
 * Настройки безопасности.
 * - HTTP Basic: email + пароль в каждом запросе, сессий нет (STATELESS);
 * - CSRF включён для всех изменяющих запросов (POST / PUT / PATCH / DELETE).
 *   Токен хранится в cookie XSRF-TOKEN (HttpOnly), клиент получает его через GET /api/auth/csrf
 *   и передаёт в заголовке X-XSRF-TOKEN;
 * - на уровне URL закрыто всё, кроме получения CSRF-токена и регистрации,
 *   управление пользователями — только с правом USERS_MANAGE;
 * - детальные правила — в @PreAuthorize на методах контроллеров и проверки владельца в сервисах.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String USERS_MANAGE = "USERS_MANAGE";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   RestAuthenticationEntryPoint entryPoint,
                                                   RestAccessDeniedHandler accessDeniedHandler, JwtService jwt, AppUserDetailsService users) throws Exception {
        http
                .csrf(csrf -> csrf.csrfTokenRepository(new CookieCsrfTokenRepository())
                        .ignoringRequestMatchers("/auth/login", "/auth/register", "/auth/refresh")
                        .ignoringRequestMatchers(AccessTokenFilter::hasBearer))
                .addFilterBefore(new AccessTokenFilter(jwt, users, entryPoint), BasicAuthenticationFilter.class)
                .httpBasic(basic -> basic.authenticationEntryPoint(entryPoint))
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register", "/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                        .requestMatchers("/api/auth/**").authenticated()

                        // управление пользователями
                        .requestMatchers(HttpMethod.GET, "/api/users").hasAuthority(USERS_MANAGE)
                        .requestMatchers(HttpMethod.POST, "/api/users").hasAuthority(USERS_MANAGE)
                        .requestMatchers(HttpMethod.DELETE, "/api/users/*").hasAuthority(USERS_MANAGE)
                        .requestMatchers("/api/users/*/role", "/api/users/*/block", "/api/users/*/unblock")
                        .hasAuthority(USERS_MANAGE)

                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /** Пароли хранятся только как BCrypt-хеши. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** События успешного / неудачного входа — их слушает LoginAttemptService. */
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }
}

