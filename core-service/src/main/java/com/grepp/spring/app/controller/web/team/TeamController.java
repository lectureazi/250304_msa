package com.grepp.spring.app.controller.web.team;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("team")
public class TeamController {

    @GetMapping("{id}")
    @PreAuthorize("hasAnyAuthority('TEAM_' + #id + ':MEMBER', 'TEAM_' + #id + ':LEADER')")
    public String teamPage(
        @PathVariable int id,
        Model model,
        Authentication authentication
    ){
        model.addAttribute("teamId", id);
        model.addAttribute("username", authentication.getName());
        return "team/team";
    }
    
    @GetMapping("{id}/dashboard")
    @PreAuthorize("hasAuthority('TEAM_' + #id + ':LEADER')")
    public String teamDashboard(
        @PathVariable int id
    ){
        return "team/team-dashboard";
    }
    
    
}
