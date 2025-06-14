package com.grepp.spring.app.controller.api.book.payload;

import com.grepp.spring.app.model.book.code.BookImgType;
import com.grepp.spring.app.model.book.dto.BookDto;
import com.grepp.spring.app.model.book.dto.BookImgDto;
import java.util.List;

public record BookListResponse(
    List<BookInfo> bookInfos
) {
    public record BookInfo(
        Long bkIdx,
        String title,
        String author,
        String thumbnail
    ){
        public static BookInfo fromDto(BookDto bookDto){
            List<BookImgDto> images = bookDto.getImages();
            if(images == null){
                return new BookInfo(
                    bookDto.getId(),
                    bookDto.getTitle(),
                    bookDto.getAuthor(),
                    null
                );
            }
            
            List<BookImgDto> thumbnail =  images.stream().
                               filter(e -> e.getType().equals(BookImgType.THUMBNAIL))
                               .toList();
            
            return new BookInfo(
                bookDto.getId(),
                bookDto.getTitle(),
                bookDto.getAuthor(),
                thumbnail.isEmpty() ? null : thumbnail.getFirst().getUrl()
            );
        }
    }
    
    public static BookListResponse fromDtoList(List<BookDto> bookDtos){
        List<BookInfo> bookInfos = bookDtos.stream().map(BookInfo::fromDto).toList();
        return new BookListResponse(bookInfos);
    }
    
}
