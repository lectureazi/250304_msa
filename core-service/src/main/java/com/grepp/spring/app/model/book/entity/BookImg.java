package com.grepp.spring.app.model.book.entity;
import com.grepp.spring.app.model.book.code.BookImgType;
import com.grepp.spring.infra.entity.BaseEntity;
import com.grepp.spring.infra.util.file.FileDto;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter @Setter @ToString
@NoArgsConstructor
public class BookImg extends BaseEntity {
    @Id
    @GeneratedValue
    private Long id;
    @Enumerated(EnumType.STRING)
    private BookImgType type;
    private String originFileName;
    private String renameFileName;
    private String savePath;
    
    public BookImg(BookImgType type, FileDto fileDto){
        this.type = type;
        this.originFileName = fileDto.originFileName();
        this.renameFileName = fileDto.renameFileName();
        this.savePath = fileDto.savePath();
    }
    
    public String getUrl(){
        return "/download/" + savePath + renameFileName;
    }
}
