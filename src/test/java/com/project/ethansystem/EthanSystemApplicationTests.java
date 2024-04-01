package com.project.ethansystem;

import com.baomidou.mybatisplus.core.toolkit.Assert;
import com.project.ethansystem.model.domain.User;
import com.project.ethansystem.service.UserService;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootTest
class EthanSystemApplicationTests {
    @Resource
    private UserService userService;

    @Test
    public void testPattern() {
        String pattern = "[a-zA-Z][a-zA-Z0-9_]{5,}", userAccount = "s12234jjjj122";
        Matcher matcher = Pattern.compile(pattern).matcher(userAccount);
        System.out.println(matcher.find());
        System.out.println(matcher.group());
        System.out.println(matcher.groupCount());
    }
}
