package com.grepp.spring.app.model.student.entity;

import com.grepp.spring.app.model.student.code.MBTI;
import com.grepp.spring.infra.entity.BaseEntity;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter @Setter
public class Student extends BaseEntity {

    @Id
    private String userId;
    private String name;
    @Enumerated(EnumType.STRING)
    private MBTI mbti;
    private String major;
    
    @Override
    public String toString() {
        return "Student{" +
                   "userId='" + userId + '\'' +
                   ", name='" + name + '\'' +
                   ", mbti=" + mbti +
                   ", personality=" + mbti.desc() +
                   ", major='" + major + '\'' +
                   '}';
    }
}
