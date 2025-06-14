package com.grepp.spring.app.model.student.document;

import com.grepp.spring.app.model.student.code.MBTI;
import com.grepp.spring.app.model.student.entity.Student;
import dev.langchain4j.data.embedding.Embedding;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.model.embedding.EmbeddingModel;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.mongodb.core.mapping.Document;

@Getter
@Setter
@NoArgsConstructor
@Document(collection = "students")
public class StudentEmbedding {

    @Id
    private String id;
    private String text;
    private float[] embedding;
    
    private String name;
    private MBTI mbti;
    private String major;
    
    public StudentEmbedding(Student entity, TextSegment segment, Embedding embedding) {
        this.id=entity.getUserId();
        this.name=entity.getName();
        this.mbti=entity.getMbti();
        this.major=entity.getMajor();
        
        this.text=segment.text();
        this.embedding=embedding.vector();
    }
    
    public static StudentEmbedding fromEntity(Student entity, EmbeddingModel model){
        TextSegment segment = TextSegment.from(entity.toString());
        Embedding embedding = model.embed(segment).content();
        return new StudentEmbedding(entity, segment, embedding);
    }
    
    public void embed(EmbeddingModel model) {
        TextSegment segment = TextSegment.from(this.toString());
        this.text = segment.text();
        Embedding embedding = model.embed(segment).content();
        this.embedding = embedding.vector();
    }
    
    @Override
    public String toString() {
        return "StudentEmbedding{" +
                   "id='" + id + '\'' +
                   ", name='" + name + '\'' +
                   ", mbti=" + mbti +
                   ", personality" + mbti.desc() + '\'' +
                   ", major='" + major + '\'' +
                   '}';
    }
}
