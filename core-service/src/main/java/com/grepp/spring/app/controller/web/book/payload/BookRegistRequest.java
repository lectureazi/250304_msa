package com.grepp.spring.app.controller.web.book.payload;

import com.grepp.spring.app.model.book.code.Category;
import com.grepp.spring.app.model.book.dto.BookDto;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class BookRegistRequest {
    
    private List<MultipartFile> thumbnail;
    @NotBlank
    private String title;
    @NotBlank
    private String author;
    @NotBlank
    private String info;
    @NotBlank
    private String category;
    
    public BookDto toDto(){
        BookDto bookDto = new BookDto();
        bookDto.setTitle(title);
        bookDto.setAuthor(author);
        bookDto.setInfo(info);
        bookDto.setCategory(Category.valueOf(category));
        return bookDto;
    }
}
