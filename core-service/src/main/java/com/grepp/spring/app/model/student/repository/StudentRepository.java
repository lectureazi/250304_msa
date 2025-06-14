package com.grepp.spring.app.model.student.repository;

import com.grepp.spring.app.model.student.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentRepository extends JpaRepository<Student, String> {

}
