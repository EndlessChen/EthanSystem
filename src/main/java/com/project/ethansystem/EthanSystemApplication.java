package com.project.ethansystem;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.project.ethansystem.mapper")
public class EthanSystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(EthanSystemApplication.class, args);
    }

}
