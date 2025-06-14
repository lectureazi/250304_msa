package com.grepp.spring.infra.feign.error

import org.springframework.http.HttpStatus

class FeignCommonException : RuntimeException {
    private var code: String? = null
    override var message: String? = null
    private var status: HttpStatus? = null

    constructor()
    constructor(cause: Throwable?) : super(cause)
    constructor(code: String?, message: String?, status: HttpStatus?) {
        this.code = code
        this.message = message
        this.status = status
    }

    constructor(cause: Throwable?, code: String?, message: String?, status: HttpStatus?) : super(
        cause
    ) {
        this.code = code
        this.message = message
        this.status = status
    }
}
