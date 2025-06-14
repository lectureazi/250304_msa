package com.grepp.spring.infra.response

@JvmRecord
data class WebSocketResponse<T>(
    val code: String,
    val message: String,
    val data: T
) {
    companion object {
        fun <T> success(data: T): WebSocketResponse<T> {
            return WebSocketResponse<T>(ResponseCode.OK.code(), ResponseCode.OK.message(), data)
        }

        fun <T> noContent(): WebSocketResponse<T?> {
            return WebSocketResponse<T?>(ResponseCode.OK.code(), ResponseCode.OK.message(), null)
        }

        fun <T> error(code: ResponseCode): WebSocketResponse<T?> {
            return WebSocketResponse(code.code(), code.message(), null)
        }

        fun <T> error(code: ResponseCode, data: T): WebSocketResponse<T> {
            return WebSocketResponse(code.code(), code.message(), data)
        }
    }
}
