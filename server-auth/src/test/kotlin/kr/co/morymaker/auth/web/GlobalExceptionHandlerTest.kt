package kr.co.morymaker.auth.web

import kr.co.morymaker.auth.application.service.account.AccountNotFoundException
import kr.co.morymaker.auth.application.service.account.EmailDuplicateException
import kr.co.morymaker.auth.application.service.account.EventAssignmentRequiredException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.HttpStatus

/**
 * [GlobalExceptionHandler] 단위 테스트 — 에러코드 매핑(§0-5)이 예외 타입별로 정확한 HTTP
 * status·code 로 변환되는지 확인한다. Spring 컨텍스트 없이 핸들러 메서드를 직접 호출한다.
 */
class GlobalExceptionHandlerTest {

    private val sut = GlobalExceptionHandler()

    @Test
    fun `EmailDuplicateException 은 409 EMAIL_DUPLICATE 로 매핑된다`() {
        val response = sut.handleEmailDuplicate(EmailDuplicateException("dup@morymaker.co.kr"))

        assertEquals(HttpStatus.CONFLICT, response.statusCode)
        assertEquals("EMAIL_DUPLICATE", response.body?.error?.code)
    }

    @Test
    fun `DuplicateKeyException 도 409 EMAIL_DUPLICATE 로 매핑된다 (DB UNIQUE 최종 방어)`() {
        val response = sut.handleEmailDuplicate(DuplicateKeyException("uk_account_email"))

        assertEquals(HttpStatus.CONFLICT, response.statusCode)
        assertEquals("EMAIL_DUPLICATE", response.body?.error?.code)
    }

    @Test
    fun `EventAssignmentRequiredException 은 422 BUSINESS_RULE 로 매핑된다`() {
        val response = sut.handleEventAssignmentRequired(EventAssignmentRequiredException("EVENT_STAFF"))

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.statusCode)
        assertEquals("BUSINESS_RULE", response.body?.error?.code)
    }

    @Test
    fun `AccountNotFoundException 은 404 NOT_FOUND 로 매핑된다`() {
        val response = sut.handleNotFound(AccountNotFoundException("missing-id"))

        assertEquals(HttpStatus.NOT_FOUND, response.statusCode)
        assertEquals("NOT_FOUND", response.body?.error?.code)
    }

    @Test
    fun `IllegalArgumentException 은 400 VALIDATION_FAILED 로 매핑된다 (role status 값 검증)`() {
        val response = sut.handleIllegalArgument(IllegalArgumentException("status는 활성 또는 비활성이어야 합니다"))

        assertEquals(HttpStatus.BAD_REQUEST, response.statusCode)
        assertEquals("VALIDATION_FAILED", response.body?.error?.code)
    }

    @Test
    fun `그 외 예외는 500 INTERNAL_ERROR 로 매핑되고 평문 메시지를 노출하지 않는다`() {
        val response = sut.handleUnexpected(RuntimeException("DB 커넥션 실패: jdbc://internal-host"))

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.statusCode)
        assertEquals("INTERNAL_ERROR", response.body?.error?.code)
        assertEquals("일시적인 오류가 발생했습니다", response.body?.error?.message)
    }
}
