package com.grepp.spring.app.model.book.dto;
import com.grepp.spring.app.model.book.code.BookImgType;
import com.grepp.spring.infra.util.file.FileDto;
import java.time.LocalDateTime;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class BookImgDto {
    private Long id;
    private BookImgType type;
    private String originFileName;
    private String renameFileName;
    private String savePath;
    private LocalDateTime createdAt;
    private Boolean activated;
    
    public BookImgDto(BookImgType type, FileDto fileDto){
        this.type = type;
        this.originFileName = fileDto.originFileName();
        this.renameFileName = fileDto.renameFileName();
        this.savePath = fileDto.savePath();
    }
    
    public String getUrl(){
        return "/download/" + savePath + renameFileName;
    }
}
