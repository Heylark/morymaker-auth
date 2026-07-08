package kr.co.morymaker.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication(scanBasePackages = ["kr.co.morymaker.auth"])
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}
