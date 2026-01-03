package com.dalmeng.gateway.security

import com.dalmeng.gateway.config.JwtProperties
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets

@Component
class JwtAuthenticationManager(
    private val jwtProperties: JwtProperties
) : ReactiveAuthenticationManager {

    private val secretKey = Keys.hmacShaKeyFor(
        jwtProperties.secret.toByteArray(StandardCharsets.UTF_8)
    )
    
    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        val token = authentication.credentials as? String
            ?: return Mono.error(BadCredentialsException("Missing JWT token"))

        return try {
            val claims: Claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .body

            val userId = claims.subject
                ?: return Mono.error(BadCredentialsException("JWT subject is missing"))

            val role = claims["role"] as? String ?: "USER"
            val authorities = listOf(
                SimpleGrantedAuthority("ROLE_$role")
            )

            Mono.just(
                JwtAuthenticationToken(
                    userId = userId,
                    authorities = authorities
                )
            )
        } catch (e: JwtException) {
            Mono.error(BadCredentialsException("Invalid JWT", e))
        }
    }
}
