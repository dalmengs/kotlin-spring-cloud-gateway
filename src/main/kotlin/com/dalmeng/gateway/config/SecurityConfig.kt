package com.dalmeng.gateway.config

import com.dalmeng.gateway.security.JwtAuthenticationConverter
import com.dalmeng.gateway.security.JwtAuthenticationFailureHandler
import com.dalmeng.gateway.security.JwtAuthenticationManager
import com.dalmeng.gateway.security.SecurityExceptionHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter

@Configuration
@EnableWebFluxSecurity
class SecurityConfig(
    private val jwtAuthenticationManager: JwtAuthenticationManager,
    private val jwtAuthenticationConverter: JwtAuthenticationConverter,
    private val jwtAuthenticationFailureHandler: JwtAuthenticationFailureHandler,
    private val securityExceptionHandler: SecurityExceptionHandler,
) {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {

        val jwtFilter = AuthenticationWebFilter(jwtAuthenticationManager).apply {
            setServerAuthenticationConverter(jwtAuthenticationConverter)
            setAuthenticationFailureHandler(jwtAuthenticationFailureHandler)
        }

        return http
            .csrf { it.disable() }
            .httpBasic { it.disable() }
            .formLogin { it.disable() }

            .authorizeExchange {
                it.pathMatchers("/health").permitAll()
                it.pathMatchers("/api/admin/**").hasRole("ADMIN")
                it.anyExchange().authenticated()
            }

            .exceptionHandling {
                it.authenticationEntryPoint(securityExceptionHandler)
                it.accessDeniedHandler(securityExceptionHandler)
            }

            .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
    }
}
