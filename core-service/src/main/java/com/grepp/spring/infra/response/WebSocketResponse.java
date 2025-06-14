package com.grepp.spring.infra.response;

public record WebSocketResponse<T>(
    String code,
    String message,
    T data
) {
    
    public static <T> WebSocketResponse<T> success(T data) {
        return new WebSocketResponse<>(ResponseCode.OK.code(), ResponseCode.OK.message(), data);
    }
    
    public static <T> WebSocketResponse<T> noContent() {
        return new WebSocketResponse<>(ResponseCode.OK.code(), ResponseCode.OK.message(), null);
    }
    
    public static <T> WebSocketResponse<T> error(ResponseCode code) {
        return new WebSocketResponse<>(code.code(), code.message(), null);
    }
    
    public static <T> WebSocketResponse<T> error(ResponseCode code, T data) {
        return new WebSocketResponse<>(code.code(), code.message(), data);
    }
}
