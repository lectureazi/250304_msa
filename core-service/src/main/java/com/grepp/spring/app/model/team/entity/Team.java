package com.grepp.spring.app.model.team.entity;

import com.grepp.spring.infra.entity.BaseEntity;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import java.time.LocalDateTime;
import java.util.List;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter
@Setter
@ToString
public class Team extends BaseEntity {
    
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    
    @OneToMany(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "teamId")
    private List<TeamMember> member;
}
