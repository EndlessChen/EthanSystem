package com.project.ethansystem;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.annotation.Configuration;

/**
 * SpringBoot 项目主类
 * @author Ethan Chen
 */

@SpringBootApplication
@MapperScan("com.project.ethansystem.mapper")
public class EthanSystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(EthanSystemApplication.class, args);
    }
}
