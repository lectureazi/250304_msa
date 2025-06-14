package com.grepp.spring.token.entity

import java.util.*

class RefreshToken(
    val id:String = UUID.randomUUID().toString(),
    var accessTokenId: String,
    var token: String = UUID.randomUUID().toString(),
    var ttl:Long = 3600 * 24 * 7,
) {

}
