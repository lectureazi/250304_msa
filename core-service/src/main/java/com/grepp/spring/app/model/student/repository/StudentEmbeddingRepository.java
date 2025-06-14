package com.grepp.spring.app.model.student.repository;

import com.grepp.spring.app.model.student.code.MBTI;
import com.grepp.spring.app.model.student.document.StudentEmbedding;
import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface StudentEmbeddingRepository
    extends MongoRepository<StudentEmbedding, String> {
    
    List<StudentEmbedding> findByMbti(MBTI mbti);
    
}
