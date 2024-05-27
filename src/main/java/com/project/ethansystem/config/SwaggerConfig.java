package com.project.ethansystem.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * 接口文档
 * @author Ethan Chen
 */

@Configuration
@Profile("prod")
public class SwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI().info(new Info()
                        .title("EthanSystem 接口文档")
                        .version("1.0")
                        .description( "EthanSystem 接口文档")
                        .license(new License().name("Apache 2.0").url("http://doc.xiaominfo.com")));
    }
}
