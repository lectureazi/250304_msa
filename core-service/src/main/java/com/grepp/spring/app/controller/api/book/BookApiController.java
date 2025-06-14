package com.grepp.spring.app.controller.api.book;

import com.grepp.spring.app.controller.api.book.payload.BookListRequest;
import com.grepp.spring.app.controller.api.book.payload.BookListResponse;
import com.grepp.spring.app.model.book.BookService;
import com.grepp.spring.app.model.book.dto.BookDto;
import com.grepp.spring.infra.response.ApiResponse;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("api/book")
@RequiredArgsConstructor
public class BookApiController {
    private final BookService bookService;
}
