package com.grepp.spring.app.model.rent;

import com.grepp.spring.app.model.rent.dto.RentDto;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RentService {

    private final RentRepository rentRepository;
    private final ModelMapper mapper;
    
    public List<RentDto> findAll(){
          return rentRepository.findAll()
                     .stream().map(e -> mapper.map(e, RentDto.class))
                     .toList();
    }
}










