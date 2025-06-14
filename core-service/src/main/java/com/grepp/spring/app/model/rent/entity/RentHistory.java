package com.grepp.spring.app.model.rent.entity;

import com.grepp.spring.app.model.rent.code.RentState;
import com.grepp.spring.infra.entity.BaseEntity;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import java.time.LocalDateTime;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter
@Setter
@ToString
public class RentHistory extends BaseEntity {
    @Id
    @GeneratedValue
    private Long id;
    @ManyToOne(cascade = CascadeType.PERSIST)
    private Rent rent;
    @ManyToOne(cascade = CascadeType.PERSIST)
    private RentBook rentBook;
    private Long bookId;
    @Enumerated(EnumType.STRING)
    private RentState state;
}
