package com.grepp.spring.app.model.book.repository;

import com.grepp.spring.app.model.book.entity.Book;
import com.grepp.spring.app.model.book.entity.QBook;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

@Slf4j
@RequiredArgsConstructor
public class BookRepositoryCustomImpl implements BookRepositoryCustom {
    
    private final JPAQueryFactory queryFactory;
    private final QBook book = QBook.book;
    
    @Override
    public Page<Book> findPaged(Pageable pageable) {
        
        List<Book> content = queryFactory
                                 .select(book)
                                 .from(book)
                                 .leftJoin(book.images)
                                 .where(book.activated)
                                 .orderBy(book.createdAt.desc())
                                 .offset(pageable.getOffset())
                                 .limit(pageable.getPageSize())
                                 .fetch();
        
        JPAQuery<Long> countQuery = queryFactory
                                        .select(book.count())
                                        .from(book)
                                        .leftJoin(book.images)
                                        .where(book.activated);
        
        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }
}
