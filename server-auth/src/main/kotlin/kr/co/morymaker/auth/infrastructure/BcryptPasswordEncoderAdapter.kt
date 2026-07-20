package kr.co.morymaker.auth.infrastructure

import kr.co.morymaker.auth.application.port.out.security.PasswordEncoderPort
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

/**
 * [PasswordEncoderPort] 구현체 — 기존 `passwordEncoder`(BCrypt, [kr.co.morymaker.auth.config.AuthorizationServerConfig])
 * 빈에 위임한다. module-application은 spring-security-crypto를 직접 의존하지 않는다([PasswordEncoderPort]
 * KDoc 참조) — 실제 BCrypt 구현은 이 어댑터가 흡수한다.
 */
@Component
class BcryptPasswordEncoderAdapter(
    private val passwordEncoder: PasswordEncoder,
) : PasswordEncoderPort {

    override fun encode(raw: String): String = passwordEncoder.encode(raw)
}
