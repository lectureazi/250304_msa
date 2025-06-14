package com.grepp.spring.app.model.book.repository;

import com.grepp.spring.app.model.book.entity.Book;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BookRepository extends JpaRepository<Book, Long>
, BookRepositoryCustom{
    

}
