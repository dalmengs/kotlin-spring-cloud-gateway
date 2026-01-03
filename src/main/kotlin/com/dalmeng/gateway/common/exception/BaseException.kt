package com.dalmeng.gateway.common.exception

abstract class BaseException(
    val statusCode: Int,
    message: String
) : RuntimeException(message)