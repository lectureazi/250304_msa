package com.grepp.spring.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

@Component
public class InternalAuthFilter extends OncePerRequestFilter {
    
    private final UserDetailsServiceImpl userDetailsService;
    
    public InternalAuthFilter(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
    
    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        
        String userId = request.getHeader("x-member-id");
        if (userId == null) {
            userId = "ANONYMOUS";
        }
        
        String roles = request.getHeader("x-member-role");
        if (roles == null) {
            roles = "ROLE_ANONYMOUS";
        }
        
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        if (!"ANONYMOUS".equals(userId) && !"ROLE_SERVER".equals(roles)) {
            authorities.addAll(userDetailsService.findAuthorities(userId));
        }
        
        authorities.add(new SimpleGrantedAuthority(roles));
        
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            userId,
            null,
            authorities
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
