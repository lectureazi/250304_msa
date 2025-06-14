package com.grepp.spring.app.model.book;

import com.grepp.spring.app.model.book.code.BookImgType;
import com.grepp.spring.app.model.book.dto.BookDto;
import com.grepp.spring.app.model.book.entity.Book;
import com.grepp.spring.app.model.book.entity.BookImg;
import com.grepp.spring.app.model.book.repository.BookRepository;
import com.grepp.spring.infra.error.exceptions.CommonException;
import com.grepp.spring.infra.response.ResponseCode;
import com.grepp.spring.infra.util.file.FileDto;
import com.grepp.spring.infra.util.file.FileUtil;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class BookService {

    private final BookRepository bookRepository;
    private final FileUtil fileUtil;
    private final ModelMapper mapper;
    
    @Transactional
    public void registBook(List<MultipartFile> thumbnail, BookDto dto) {
        try {
            List<FileDto> fileDtos = fileUtil.upload(thumbnail, "book");
            Book book = mapper.map(dto, Book.class);
            
            if(fileDtos.isEmpty()) return;
            
            BookImg bookImg = new BookImg(BookImgType.THUMBNAIL, fileDtos.getFirst());
            book.setImages(List.of(bookImg));
            bookRepository.save(book);
        } catch (IOException e) {
            throw new CommonException(ResponseCode.INTERNAL_SERVER_ERROR, e);
        }
    }
    
    public List<BookDto> findAll() {
        return bookRepository.findAll()
                   .stream().map(e -> mapper.map(e, BookDto.class))
                   .toList();
    }
    
    public Page<BookDto> findPaged(Pageable pageable) {
        return bookRepository.findPaged(pageable)
                   .map(e -> mapper.map(e, BookDto.class));
    }
}
