package com.grepp.auth.infra.config

import org.modelmapper.ModelMapper
import org.modelmapper.convention.MatchingStrategies
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ModelMapperConfig {
    @Bean
    fun modelMapper(): ModelMapper {
        val modelMapper = ModelMapper()
        modelMapper.configuration.setSkipNullEnabled(true)
        modelMapper.configuration.setPreferNestedProperties(false)
        modelMapper.configuration.setMatchingStrategy(MatchingStrategies.LOOSE)
        return modelMapper
    }
}
