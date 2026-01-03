package com.dalmeng.gateway.filter

import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class UserHeaderFilter : GlobalFilter {

    override fun filter(
        exchange: ServerWebExchange,
        chain: GatewayFilterChain
    ): Mono<Void> {

        return exchange.getPrincipal<Authentication>()
            .flatMap { authentication ->

                val userId = authentication.name

                val mutatedExchange = exchange.mutate()
                    .request { request ->
                        request.header("X-User-Id", userId)
                    }
                    .build()

                chain.filter(mutatedExchange)
            }
            .switchIfEmpty(
                chain.filter(exchange)
            )
    }
}
