package kr.co.morymaker.auth.web

import com.fasterxml.jackson.databind.exc.MismatchedInputException
import kr.co.morymaker.auth.application.service.account.AccountNotFoundException
import kr.co.morymaker.auth.application.service.account.EmailDuplicateException
import kr.co.morymaker.auth.application.service.account.EventAssignmentRequiredException
import kr.co.morymaker.auth.dto.ErrorBody
import kr.co.morymaker.auth.dto.ErrorDetail
import org.slf4j.LoggerFactory
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.servlet.NoHandlerFoundException
import org.springframework.web.servlet.resource.NoResourceFoundException

/**
 * §3 어드민 REST의 공통 에러 응답 변환(api Event/Guest 어드민 패턴의 auth 자체 사본, 별도
 * repo라 공유 불가). 401 UNAUTHENTICATED·403 ROLE_FORBIDDEN은 여기 도달하지 않는다 — 필터 레벨
 * [kr.co.morymaker.auth.config.AdminApiSecurityConfig]의 인증/인가 핸들러가 먼저 처리한다.
 */
@RestControllerAdvice
class GlobalExceptionHandler {

    private val log = LoggerFactory.getLogger(javaClass)

    // 서비스 pre-check(EmailDuplicateException, fast-path)와 DB UNIQUE 위반(DuplicateKeyException,
    // 동시성 최종 방어) 둘 다 같은 409로 매핑한다 — 호출자 관점에서는 동일한 실패다.
    @ExceptionHandler(EmailDuplicateException::class, DuplicateKeyException::class)
    fun handleEmailDuplicate(e: Exception): ResponseEntity<ErrorBody> =
        ResponseEntity.status(HttpStatus.CONFLICT)
            .body(ErrorBody(ErrorDetail("EMAIL_DUPLICATE", e.message ?: "이미 사용 중인 이메일입니다")))

    // 역할↔eventIds 규칙 위반(§0-5 비즈니스 규칙 범주) — 필드 형식 오류(400)와 구분되는 422.
    @ExceptionHandler(EventAssignmentRequiredException::class)
    fun handleEventAssignmentRequired(e: EventAssignmentRequiredException): ResponseEntity<ErrorBody> =
        ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
            .body(ErrorBody(ErrorDetail("BUSINESS_RULE", e.message ?: "행사할당 규칙을 확인해 주세요")))

    @ExceptionHandler(AccountNotFoundException::class, NoSuchElementException::class)
    fun handleNotFound(e: Exception): ResponseEntity<ErrorBody> =
        ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ErrorBody(ErrorDetail("NOT_FOUND", e.message ?: "계정을 찾을 수 없습니다")))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(e: MethodArgumentNotValidException): ResponseEntity<ErrorBody> {
        val fieldError = e.bindingResult.fieldErrors.firstOrNull()
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(
                ErrorBody(
                    ErrorDetail(
                        code = "VALIDATION_FAILED",
                        message = fieldError?.defaultMessage ?: "입력값을 확인해 주세요",
                        field = fieldError?.field,
                    ),
                ),
            )
    }

    // Kotlin data class 요청 바디에 non-null 필드가 JSON에서 통째로 빠지면 @Valid가 도달하기 전
    // 역직렬화 자체가 실패한다(jackson-module-kotlin이 MismatchedInputException 계열을 던짐) — api
    // GlobalExceptionHandler 실측(EventCreateRequest.name 누락)과 동일 함정.
    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleMessageNotReadable(e: HttpMessageNotReadableException): ResponseEntity<ErrorBody> {
        val field = (e.cause as? MismatchedInputException)?.path?.lastOrNull()?.fieldName
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ErrorBody(ErrorDetail("VALIDATION_FAILED", "요청 본문을 확인해 주세요", field)))
    }

    // AccountAdminService.validateRoleAndEvents(role 3역할 검증)·toggleStatus(status 값 검증)가
    // require(...)로 던지는 형식 오류 — @Valid로 표현할 수 없는 값 검증 실패.
    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgument(e: IllegalArgumentException): ResponseEntity<ErrorBody> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ErrorBody(ErrorDetail("VALIDATION_FAILED", e.message ?: "입력값을 확인해 주세요")))

    @ExceptionHandler(NoResourceFoundException::class, NoHandlerFoundException::class)
    fun handleNoResourceFound(e: Exception): ResponseEntity<ErrorBody> =
        ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ErrorBody(ErrorDetail("NOT_FOUND", "요청한 경로를 찾을 수 없습니다")))

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception): ResponseEntity<ErrorBody> {
        log.error("처리되지 않은 예외", e)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ErrorBody(ErrorDetail("INTERNAL_ERROR", "일시적인 오류가 발생했습니다")))
    }
}
