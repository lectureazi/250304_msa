package com.grepp.spring.app.model.team;

import com.grepp.spring.app.model.team.entity.Team;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TeamRepository extends JpaRepository<Team, Long> {

}
