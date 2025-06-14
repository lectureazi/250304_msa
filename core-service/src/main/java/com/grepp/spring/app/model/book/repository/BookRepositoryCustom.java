package com.grepp.spring.app.model.book.repository;

import com.grepp.spring.app.model.book.entity.Book;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface BookRepositoryCustom {
    Page<Book> findPaged(Pageable pageable);
}
