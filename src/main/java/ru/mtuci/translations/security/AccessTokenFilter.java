package ru.mtuci.translations.security;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

public class AccessTokenFilter extends OncePerRequestFilter {
    private final JwtService jwt;
    private final AppUserDetailsService users;
    private final RestAuthenticationEntryPoint errors;

    public AccessTokenFilter(JwtService jwt, AppUserDetailsService users, RestAuthenticationEntryPoint errors) {
        this.jwt = jwt;
        this.users = users;
        this.errors = errors;
    }

    public static boolean hasBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return header != null && header.regionMatches(true, 0, "Bearer ", 0, 7);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (hasBearer(request)) {
            try {
                var user = users.loadTokenOwner(jwt.verifyAccess(request.getHeader("Authorization").substring(7)));
                user.eraseCredentials();
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
                SecurityContextHolder.setContext(context);
            } catch (AuthenticationException ex) {
                SecurityContextHolder.clearContext();
                errors.commence(request, response, ex);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
