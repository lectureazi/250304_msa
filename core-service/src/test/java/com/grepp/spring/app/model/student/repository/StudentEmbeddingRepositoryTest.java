package com.grepp.spring.app.model.student.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.grepp.spring.app.model.student.code.MBTI;
import com.grepp.spring.app.model.student.document.StudentEmbedding;
import com.grepp.spring.app.model.student.entity.Student;
import dev.langchain4j.model.embedding.EmbeddingModel;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class StudentEmbeddingRepositoryTest {

    @Autowired
    StudentEmbeddingRepository studentEmbeddingRepository;
    @Autowired
    EmbeddingModel model;
    
    @Test
    public void save(){
        Student student = new Student();
        student.setUserId("test");
        student.setName("test");
        student.setMbti(MBTI.ENTP);
        student.setMajor("backend");
        
        studentEmbeddingRepository.save(StudentEmbedding.fromEntity(student, model));
        assertThat(studentEmbeddingRepository.existsById("test"))
            .isTrue();
    }
    
    @Test
    public void findByMbti(){
        studentEmbeddingRepository.findByMbti(MBTI.INFP)
            .forEach(System.out::println);
    }
    
    @Test
    public void update(){
        StudentEmbedding embedding = studentEmbeddingRepository.findById("test").get();
        embedding.setMbti(MBTI.INFP);
        embedding.embed(model);
        
        studentEmbeddingRepository.save(embedding);
        studentEmbeddingRepository.findByMbti(MBTI.INFP)
            .forEach(System.out::println);
    }
    
    @Test
    public void delete(){
        studentEmbeddingRepository.deleteById("test");
        assertThat(studentEmbeddingRepository.existsById("test"))
            .isFalse();
    }
    
    
}