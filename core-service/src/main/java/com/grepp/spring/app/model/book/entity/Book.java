package com.grepp.spring.app.model.book.entity;

import com.grepp.spring.app.model.book.code.Category;
import com.grepp.spring.infra.entity.BaseEntity;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.DynamicInsert;

@Entity
@DynamicInsert
@Getter @Setter @ToString
public class Book extends BaseEntity {
    @Id
    @GeneratedValue
    private Long id;
    private String title;
    private String author;
    @Enumerated(EnumType.STRING)
    private Category category;
    private String info;
    private Integer amount;
    private Integer rentCnt;
    
    @OneToMany(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "book_id")
    private List<BookImg> images = new ArrayList<>();
}
