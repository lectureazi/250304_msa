package com.grepp.spring.app.model.rent;

import com.grepp.spring.app.model.rent.entity.Rent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RentRepository extends JpaRepository<Rent, Long> {

}
