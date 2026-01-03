package com.dalmeng.gateway.security

import com.dalmeng.gateway.common.response.BaseResponse
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.ExpiredJwtException
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class JwtAuthenticationFailureHandler(
    private val objectMapper: ObjectMapper
) : ServerAuthenticationFailureHandler {

    override fun onAuthenticationFailure(
        webFilterExchange: WebFilterExchange,
        exception: org.springframework.security.core.AuthenticationException
    ): Mono<Void> {
        val response = webFilterExchange.exchange.response

        if (response.isCommitted) {
            return Mono.empty()
        }

        response.statusCode = HttpStatus.UNAUTHORIZED
        response.headers.contentType = MediaType.APPLICATION_JSON

        val message = when (exception.cause) {
            is ExpiredJwtException -> "JWT expired"
            else -> "Invalid JWT"
        }

        val body = BaseResponse.error(
            statusCode = HttpStatus.UNAUTHORIZED.value(),
            message = message
        )

        val buffer = response.bufferFactory()
            .wrap(objectMapper.writeValueAsBytes(body))

        return response.writeWith(Mono.just(buffer))
    }
}
