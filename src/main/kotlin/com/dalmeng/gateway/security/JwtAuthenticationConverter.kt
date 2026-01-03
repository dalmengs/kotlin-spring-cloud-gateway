package com.dalmeng.gateway.security

import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.http.HttpHeaders

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class JwtAuthenticationConverter: ServerAuthenticationConverter {
    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
        val authHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
            ?: return Mono.empty()

        if (!authHeader.startsWith("Bearer ")) return Mono.empty()

        val token = authHeader.removePrefix("Bearer ").trim()
        return Mono.just(UsernamePasswordAuthenticationToken(null, token))
    }
}