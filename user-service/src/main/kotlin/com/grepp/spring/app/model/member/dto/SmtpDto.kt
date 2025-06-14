package com.grepp.spring.app.model.member.dto

data class SmtpDto(
    val from:String,
    val subject:String,
    val to:List<String>,
    val properties:MutableMap<String, String> = mutableMapOf(),
    val eventType:String,
) {
}