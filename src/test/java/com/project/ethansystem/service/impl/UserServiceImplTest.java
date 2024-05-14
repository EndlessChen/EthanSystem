package com.project.ethansystem.service.impl;

import com.project.ethansystem.service.UserService;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@SpringBootTest
class UserServiceImplTest {
    @Resource
    private UserService userService;

    @Test
    public void testRegister() {
        String userAccount = "EthanChen", userPassword = "12345678", verifyPassword = "12345678", userEmail = "1913390362@qq.com";
        String inviteCode = UUID.randomUUID().toString();
        // 1. 输入信息存在空值时无法注册
        verifyPassword = "";
        Long id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 2. 输入信息不合规时无法注册
        userPassword = "12345";
        verifyPassword = "12345";
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 3. 用户账户存在时无法注册
        userPassword = "12345678";
        verifyPassword = "12345678";
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 4. 两次密码不一致时无法注册
        userAccount = "AlanWalker";
        userPassword = "222222222222";
        verifyPassword = "1111111111111";
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 5. 邀请码不合规时无法注册
        userPassword = "11111111";
        verifyPassword = userPassword;
        inviteCode = "1234567";
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 6. 账户存在特殊字符时无法注册
        userAccount = "Alan&Walker";
        inviteCode = UUID.randomUUID().toString();
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        Assertions.assertEquals(-1L, id);
        // 7. 成功注册
        userAccount = "AlanWalker";
        id = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
        System.out.println("id: " + id);
    }


    @Test
    void userUpdate() {
        String userEmail = "ss12356789qq.com";
        // 判断邮件格式是否正确
        String validEmailPattern = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*";
        Matcher EmailMatcher = Pattern.compile(validEmailPattern).matcher(userEmail);
        if (!EmailMatcher.find() || !EmailMatcher.group().equals(userEmail)) System.out.println("false");
        else System.out.println("true");
    }
}