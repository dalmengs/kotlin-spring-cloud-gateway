package com.dalmeng.gateway.security

import com.dalmeng.gateway.common.response.BaseResponse
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class SecurityExceptionHandler(
    private val objectMapper: ObjectMapper
) : ServerAuthenticationEntryPoint, ServerAccessDeniedHandler {

    override fun commence(
        exchange: ServerWebExchange,
        ex: AuthenticationException?
    ): Mono<Void> {
        return handleResponse(
            exchange.response,
            HttpStatus.UNAUTHORIZED,
            "Unauthorized"
        )
    }

    override fun handle(
        exchange: ServerWebExchange,
        denied: AccessDeniedException?
    ): Mono<Void> {
        return handleResponse(
            exchange.response,
            HttpStatus.FORBIDDEN,
            "Access Denied"
        )
    }

    private fun handleResponse(
        response: ServerHttpResponse,
        status: HttpStatus,
        message: String
    ): Mono<Void> {
        response.statusCode = status
        response.headers.contentType = MediaType.APPLICATION_JSON

        val baseResponse = BaseResponse.error(
            statusCode = status.value(),
            message = message
        )

        val jsonBytes = objectMapper.writeValueAsBytes(baseResponse)
        val buffer: DataBuffer = response.bufferFactory().wrap(jsonBytes)

        return response.writeWith(Mono.just(buffer))
    }
}
