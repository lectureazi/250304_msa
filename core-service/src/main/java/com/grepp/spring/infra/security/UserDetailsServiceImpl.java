package com.grepp.spring.infra.security;

import com.grepp.spring.app.model.team.TeamMemberRepository;
import com.grepp.spring.app.model.team.entity.TeamMember;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserDetailsServiceImpl implements UserDetailsService {
    
    private final TeamMemberRepository teamMemberRepository;
    
    @Value("${app.rest-apikey}")
    private String apiKey;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User("core-service",
            apiKey,
            List.of(new SimpleGrantedAuthority("ROLE_SERVER")));
    }
    
    @Cacheable("user-authorities")
    public List<SimpleGrantedAuthority> findAuthorities(String username){
        List<TeamMember> teamMembers = teamMemberRepository.findByUserIdAndActivated(username, true);
        List<SimpleGrantedAuthority> teamAuthorities =
            teamMembers.stream().map(e -> new SimpleGrantedAuthority("TEAM_" + e.getTeamId() + ":" + e.getRole()))
                .toList();
        return new ArrayList<>(teamAuthorities);
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
}
