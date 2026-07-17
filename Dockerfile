# auth/Dockerfile — Gradle 멀티모듈(:server-auth:bootJar)을 담는 2스테이지 이미지.
# 저장소에 Gradle toolchain 선언이 없고 빌드 JDK 경로를 고정하는 gradle.properties 는
# gitignored 라, 베이스 이미지 태그가 빌드 JDK를 고정하는 유일한 수단이다.
#
# api(Dockerfile)와 동일 계보 — 미러 + 단순화. auth는 context-path·AJP 커넥터 자체가 없어
# (루트 유지) Ghostcat 하드닝·AJP_SECRET·prod 프로필 블록을 전량 배제한다(누락 아님. 근거는
# 각 배제 지점 주석 참조).

# ────────────────────────────────────────────────────────────────────
# stage 1: builder
# ────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:17.0.19_10-jdk AS builder

WORKDIR /src

# 빌드 스크립트·wrapper만 먼저 COPY — 소스가 바뀌어도 의존성 다운로드 레이어는 캐시로 남는다.
COPY gradlew ./
COPY gradle/ ./gradle/
COPY settings.gradle.kts build.gradle.kts ./
COPY module-domain/build.gradle.kts ./module-domain/
COPY module-application/build.gradle.kts ./module-application/
COPY module-persistence/build.gradle.kts ./module-persistence/
COPY server-auth/build.gradle.kts ./server-auth/

# 이 레이어가 캐시하는 것은 의존성 "메타데이터"뿐이다. 앱 jar 는 받지 않는다 — `dependencies` 는
# 리포트 태스크라 그래프만 해석하고 아티팩트를 내려받지 않기 때문이다. 소스가 바뀌면 앱 jar 는
# 매번 다시 받는다 — 이 레이어가 아끼는 건 메타데이터 왕복분이지 jar 다운로드가 아니다.
# ⚠️ 프로젝트(:server-auth)를 반드시 명시할 것 — `dependencies` 만 쓰면 루트 프로젝트만 실행되는데
#    root 는 subprojects{} 로 자식에만 플러그인을 적용해 자신은 구성이 0건이라, 메타데이터조차
#    한 건도 안 받고 조용히 통과한다.
RUN ./gradlew :server-auth:dependencies --no-daemon

# 나머지 소스 COPY (.dockerignore 가 build/·.gradle/·gradle.properties 등을 컨텍스트에서 제외한다)
COPY . .

# :server-auth:bootJar 단독 실행 — 이 태스크 그래프엔 test 가 없고(테스트 미실행) plain jar 도
# 생성되지 않아 산출물은 항상 정확히 1개다. 그래도 "정확히 1개"를 셸로 단언한다 — 미래에
# 누군가 이 스테이지를 `./gradlew build` 로 바꾸면 plain jar 가 섞여 들어와 아래 글롭이 조용히
# 2개를 매칭하게 된다. 그 순간을 시끄럽게 만드는 것이 이 가드의 목적이다.
RUN ./gradlew :server-auth:bootJar --no-daemon \
 && set -eu; \
    mkdir -p /app; \
    n=$(ls -1 server-auth/build/libs/*.jar | wc -l); \
    [ "$n" -eq 1 ] || { echo "FATAL: bootJar 산출물이 1개가 아님(n=$n) — plain jar 혼입 의심"; ls -l server-auth/build/libs/; exit 1; }; \
    mv server-auth/build/libs/*.jar /app/app.jar

# ────────────────────────────────────────────────────────────────────
# stage 2: runtime — 표준 JRE 유지.
# auth는 AWT/QR 미사용(zxing·java.desktop 의존 0건 — 전 소스 실측 확인)이라 full JRE가 런타임
# 요구는 아니다. 그래도 최소화하지 않는 이유: ① 최저위험 표준 베이스 ② api와 동일 patch tag로
# 이미지 계보 일관(재현성) ③ jlink 커스텀/distroless는 단일 테넌트 스테이징에 복잡도만 추가
# (YAGNI) ④ 향후 auth에 이미지 처리가 유입되면 선제 안전. slim/distroless 최소화는 보류한다.
# ────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:17.0.19_10-jre AS runtime

RUN groupadd -r morymaker && useradd -r -g morymaker morymaker

WORKDIR /app
COPY --from=builder --chown=morymaker:morymaker /app/app.jar /app/app.jar

USER morymaker

EXPOSE 30000
# AJP 미노출 대상 자체가 없다 — auth는 전용 서브도메인(mm-accounts) 루트 프록시로만 붙는다.
# context-path·AJP 커넥터가 코드에 없으므로(00-research 실측) Ghostcat 하드닝·AJP_SECRET
# 주입 로직 자체를 배제했다(api 대비 누락이 아니라 auth 표면에 대상이 없다는 뜻).

# health 는 DB 가용성을 집계에 포함한다(DataSourceHealthIndicator) — 앱 기동은 빨라도 DB 준비가
# 늦으면 그 사이 DOWN 이 뜬다. --start-period 없이 붙이면 컨테이너가 뜨자마자 unhealthy 로
# 낙인찍힌다. 경로는 /actuator/health — auth는 servlet context-path 가 루트라 /api 접두가
# 없다(api Dockerfile을 그대로 복붙하면 /api/actuator/health 로 영구 404가 난다).
HEALTHCHECK --start-period=30s --interval=10s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:30000/actuator/health || exit 1

# exec form — java 가 PID 1 로 SIGTERM 을 직접 받는다(shell form 이면 sh 가 PID 1 이 되어
# graceful shutdown 이 깨진다). 프로필·시크릿은 이미지에 굽지 않는다 — 전부 런타임 env 로만
# 주입한다.
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
