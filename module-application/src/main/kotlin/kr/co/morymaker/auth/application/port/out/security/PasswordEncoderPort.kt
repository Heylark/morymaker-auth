package kr.co.morymaker.auth.application.port.out.security

/**
 * 비밀번호 인코딩 port-out — §3-2 초기 비밀번호 발급(관리자 지정 방식)이 이 포트를 통해 해시를
 * 만든다.
 *
 * module-application은 spring-security-crypto를 직접 의존하지 않는다([EventScopePort] 패턴
 * 정합) — 실제 구현(BCrypt)은 server-auth가 기존 `passwordEncoder` 빈에 위임한다.
 */
interface PasswordEncoderPort {

    /** 원문을 해시로 인코딩한다. */
    fun encode(raw: String): String
}
