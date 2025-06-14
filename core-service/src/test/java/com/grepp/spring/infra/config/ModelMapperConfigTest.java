package com.grepp.spring.infra.config;

import static org.junit.jupiter.api.Assertions.*;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;

class ModelMapperConfigTest {
    
    @Test
    public void mapperTest(){
        Order order = new Order(
            new Customer(new Name("md", "ha")),
            new Address("seoul", "samsung"));
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.LOOSE);
        
        OrderDTO dto = modelMapper.map(order, OrderDTO.class);
        System.out.println(dto);
        assertEquals(order.getCustomer().getName().getFirstName(), dto.getCustomerFirstName());
        assertEquals(order.getCustomer().getName().getLastName(), dto.getCustomerLastName());
        assertEquals(order.getBillingAddress().getStreet(), dto.getBillingStreet());
        assertEquals(order.getBillingAddress().getCity(), dto.getBillingCity());
    }
    
    
    @AllArgsConstructor
    @Data
    static class Order {
        Customer customer;
        Address billingAddress;
    }
    
    @AllArgsConstructor
    @Data
    static class Customer {
        Name name;
    }
    
    @AllArgsConstructor
    @Data
    static class Name {
        String firstName;
        String lastName;
    }
    
    @AllArgsConstructor
    @Data
    static class Address {
        String street;
        String city;
    }
    
    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    static class OrderDTO {
        private String customerFirstName;
        private String customerLastName;
        private String billingStreet;
        private String billingCity;
    }

}