package com.project.ethansystem.utils;

import jakarta.annotation.Resource;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
@Data
@ConfigurationProperties(prefix = "spring.mail")
public class EmailUtils {
    @Resource
    private JavaMailSender mailSender;

    private String username;

    /**
     * 发送验证码给用户修改密码
     * @param to 要发送的用户邮箱
     * @param verificationCode 用来验证的验证码
     */
    public void sendMail(String to, String verificationCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(username);
        message.setTo(to);
        message.setSubject("Ethan System 验证码");
        message.setText("您正在尝试重置密码，验证码：" + verificationCode);
        mailSender.send(message);
    }
}
