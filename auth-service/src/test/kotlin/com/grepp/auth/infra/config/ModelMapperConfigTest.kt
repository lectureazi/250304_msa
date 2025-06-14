package com.grepp.auth.infra.config

import com.grepp.auth.app.model.member.code.Role
import com.grepp.auth.app.model.member.entity.Member
import com.grepp.auth.infra.annotation.NoArgsConstructor
import org.modelmapper.ModelMapper
import org.modelmapper.convention.MatchingStrategies
import kotlin.test.Test

class ModelMapperTest{

    @Test
    fun testMapper(){
        println("===========================")
        val modelMapper = ModelMapper()
        modelMapper.configuration.setMatchingStrategy(MatchingStrategies.LOOSE)

        val member = Member("test","1234",
            "test@test.com", Role.ROLE_USER,"01022223333")

        val response = modelMapper.map(member, SignupResponse::class.java)
        println(response)

    }
}

@NoArgsConstructor
data class SignupResponse(
    var userId:String,
    var email:String,
    var tel:String
)