package com.grepp.spring.app.model.team;

import com.grepp.spring.app.model.team.entity.TeamMember;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TeamMemberRepository extends JpaRepository<TeamMember, Long> {
    List<TeamMember> findByUserIdAndActivated(String userId, Boolean activated);
}
