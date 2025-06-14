package com.grepp.spring.app.model.team.entity;

import com.grepp.spring.app.model.team.code.TeamRole;
import com.grepp.spring.infra.entity.BaseEntity;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import java.time.LocalDateTime;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter
@Setter
@ToString
public class TeamMember extends BaseEntity {
    @Id
    @GeneratedValue
    private Long id;
    private Long teamId;
    private String userId;
    @Enumerated(EnumType.STRING)
    private TeamRole role;
}
