package kr.co.morymaker.auth

import kr.co.morymaker.auth.config.AuthProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication(scanBasePackages = ["kr.co.morymaker.auth"])
@EnableConfigurationProperties(AuthProperties::class)
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}
