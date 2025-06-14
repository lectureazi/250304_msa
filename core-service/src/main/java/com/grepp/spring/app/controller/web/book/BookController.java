package com.grepp.spring.app.controller.web.book;

import com.grepp.spring.app.controller.web.book.payload.BookRegistRequest;
import com.grepp.spring.app.model.book.BookService;
import com.grepp.spring.app.model.book.code.Category;
import com.grepp.spring.app.model.book.dto.BookDto;
import com.grepp.spring.infra.error.exceptions.CommonException;
import com.grepp.spring.infra.payload.PageParam;
import com.grepp.spring.infra.response.PageResponse;
import com.grepp.spring.infra.response.ResponseCode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
@RequestMapping("book")
@RequiredArgsConstructor
public class BookController {
    
    private final BookService bookService;
    
    @GetMapping("regist")
    public String regist(BookRegistRequest form, Model model) {
        model.addAttribute("category", Category.values());
        return "book/book-regist";
    }
    
    @PostMapping("regist")
    public String regist(@Valid BookRegistRequest form, BindingResult bindingResult
        , Model model) {
        
        if (bindingResult.hasErrors()) {
            model.addAttribute("category", Category.values());
            return "book/book-regist";
        }
        
        bookService.registBook(form.getThumbnail(), form.toDto());
        return "redirect:/";
    }
    
    @GetMapping("list")
    public String list(
        @Valid
        PageParam param,
        BindingResult bindingResult,
        Model model) {
        
        if (bindingResult.hasErrors()) {
            throw new CommonException(ResponseCode.BAD_REQUEST);
        }
        
        Pageable pageable = PageRequest.of(param.getPage() - 1, param.getSize());
        Page<BookDto> page = bookService.findPaged(pageable);
        
        if(param.getPage() != 1 && page.getContent().isEmpty()){
            throw new CommonException(ResponseCode.BAD_REQUEST);
        }
        
        PageResponse<BookDto> response = new PageResponse<>("/book/list", page, 2);
        model.addAttribute("page", response);
        return "book/book-list";
    }
}
