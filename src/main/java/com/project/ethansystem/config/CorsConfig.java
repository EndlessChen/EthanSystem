package com.project.ethansystem.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {
    // @Override
    // public void addCorsMappings(CorsRegistry registry) {
    //     registry.addMapping("/**")
    //             .allowedOrigins("http://localhost:3000", "http://121.41.115.199", "http://8.130.30.154")
    //             .allowCredentials(true)
    //             .allowedMethods("GET", "POST", "PUT", "DELETE")
    //             .allowedHeaders("*")
    //             .maxAge(3600);
    // }
}
