package com.grepp.spring.app.model.rent.entity;

import com.grepp.spring.infra.entity.BaseEntity;
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
@Getter @Setter @ToString
public class Rent extends BaseEntity {
    @Id
    @GeneratedValue
    private Long id;
    private String userId;
    private Boolean isReturn;
    private String title;
    private Integer rentBookCnt;
    
    @OneToMany
    @JoinColumn(name = "rentId")
    private List<RentBook> rentBooks;
}
