package com.grepp.spring.infra.feign.config

import feign.RequestInterceptor
import feign.RequestTemplate
import org.slf4j.LoggerFactory
import org.springframework.cloud.openfeign.EnableFeignClients
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class FeignCommonConfig {

    private val log = LoggerFactory.getLogger(javaClass)

    @Bean
    fun requestOptions(): feign.Request.Options {
        return feign.Request.Options(
            5,
            java.util.concurrent.TimeUnit.SECONDS,
            10,
            java.util.concurrent.TimeUnit.SECONDS,
            true
        )
    }

    @Bean
    fun requestInterceptor(): RequestInterceptor {
        return RequestInterceptor { requestTemplate: RequestTemplate? ->
            log.info("=========================================================")
            log.info("requestTemplate : {}", requestTemplate)
        }
    }
}
