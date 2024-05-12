package com.project.ethansystem.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.project.ethansystem.common.ErrorCode;
import com.project.ethansystem.constant.UserConstant;
import com.project.ethansystem.exception.BusinessException;
import com.project.ethansystem.model.domain.User;
import com.project.ethansystem.service.UserService;
import com.project.ethansystem.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
* @author Ethan
* @description 针对表【user(用户)】的数据库操作Service实现
* @createDate 2024-03-15 00:17:30
*/
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    /**
     * 用户注册
     * @param userAccount 用户账户
     * @param password 用户密码
     * @param verifyPassword 验证密码
     * @param inviteCode 用户邀请码
     * @return 返回用户账户 id
     */
    @Override
    public Long userRegister(String userAccount, String password, String verifyPassword, String userEmail, String inviteCode) {
        // 验证数据是否为空
        if (StringUtils.isAnyBlank(userAccount, password, verifyPassword, inviteCode)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        // 验证账户是否小于 5 位，密码是否小于 8 位，密码与验证密码是否相等
        if (userAccount.length() < 5 || password.length() < 8 || !password.equals(verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 判断账号是否有特殊字符
        if (!userAccountVerify(userAccount)) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "用户账户存在特殊字符");
        // 判断邮件是否合法
        if (StringUtils.isNotBlank(userEmail) && !userEmailVerify(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误，请重新输入");
        // todo: 查看邀请码是否正确 1) 邀请码不可以重复 2) 邀请码长度均为 36 位
        // if (inviteCode.length() != 36 ) return -1L;
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User user = this.getOne(queryWrapper);
        if (user != null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户已存在");
        // todo 还需要判断邀请码是否在系统中有生成，如果没有就拒绝注册
        // 给用户输入的密码加密
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + password).getBytes());
        // 把数据保存在数据库中
        User finalUser = new User();
        finalUser.setUserAccount(userAccount);
        finalUser.setUserPassword(safetyPassword);
        finalUser.setUserEmail(userEmail);
        finalUser.setUsername(userAccount);     // 把用户昵称的默认值改成用户账户，防止前端显示出现问题
        finalUser.setInviteCode(inviteCode);
        boolean saveStatus = this.save(finalUser);
        if (!saveStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "数据库异常，请稍后再试");
        return finalUser.getUserId();
    }

    /**
     * 用户注册(仅限管理员)
     * @param user 用户对象
     * @return 是否注册成功
     */
    @Override
    public boolean userRegister(User user) {
        String userAccount = user.getUserAccount();
        String userPassword = user.getUserPassword();
        String username = user.getUsername();
        Integer userSex = user.getUserSex();
        String userAvatar = user.getUserAvatar();
        String userEmail = user.getUserEmail();
        String userRole = user.getUserRole();
        // 验证数据是否合法
        if (StringUtils.isAnyBlank(userAccount, userPassword, userRole)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        if (userSex != null && userSex != 0 && userSex != 1) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 验证账户是否小于 5 位，密码是否小于 8 位，密码与验证密码是否相等
        if (userAccount.length() < 5 || userPassword.length() < 8) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 判断邮件是否合法
        if (StringUtils.isNotBlank(userEmail) && !userEmailVerify(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误，请重新输入");
        // 判断账号是否有特殊字符
        if (!userAccountVerify(userAccount)) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "用户账户存在特殊字符");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User searchUser = this.getOne(queryWrapper);
        if (searchUser != null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户已存在");
        // 给用户输入的密码加密
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + userPassword).getBytes());
        // 把数据保存在数据库中
        User finalUser = new User();
        finalUser.setUserAccount(userAccount);
        finalUser.setUserPassword(safetyPassword);
        finalUser.setUsername(StringUtils.isBlank(username) ? userAccount : username);
        finalUser.setUserSex(userSex);
        finalUser.setUserAvatar(userAvatar);
        finalUser.setUserEmail(userEmail);
        finalUser.setUserRole(userRole);
        finalUser.setInviteCode(UUID.randomUUID().toString());
        boolean saveStatus = this.save(finalUser);
        if (!saveStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "数据库异常，请稍后再试");
        return true;
    }

    /**
     * 用户登陆
     * @param userAccount 用户账户
     * @param password 用户密码
     * @param request 请求对象
     * @return 登陆成功的用户对象
     */
    @Override
    public User userLogin(String userAccount, String password, HttpServletRequest request) {
        // 判断数据是否为空
        if (StringUtils.isAnyBlank(userAccount, password)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        // 判断账户长度是否小于 5 位、密码长度是否小于 8 位
        if (userAccount.length() < 5 || password.length() < 8) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 判断账户中是否有特殊字符
        String validAccountPattern = "[a-zA-Z][a-zA-Z0-9_]{4,}";
        Matcher matcher = Pattern.compile(validAccountPattern).matcher(userAccount);
        if (!matcher.find() || !matcher.group().equals(userAccount)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户账户存在特殊字符");
        // 把前端数据和数据库中的数据进行比较，判断是否匹配
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + password).getBytes());
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User targetUser = this.getOne(queryWrapper);
        if (targetUser == null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");    // 账户不存在
        if (!targetUser.getUserPassword().equals(safetyPassword)) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "密码错误");      // 密码错误
        // 判断用户状态是否正常，只有状态正常才可以登陆使用
        if (targetUser.getUserStatus().equals(UserConstant.USER_ABNORMAL)) throw new BusinessException(ErrorCode.NULL_ERROR, "用户状态异常，请联系管理员处理");
        // 数据脱敏
        User safetyUser = getSafetyUser(targetUser);
        // 保存用户登陆状态
        request.getSession().setAttribute(UserConstant.LOGIN_STATUS, safetyUser);
        return safetyUser;
    }

    /**
     * 修改数据
     * @param user 数据对象
     * @return 修改好的对象
     */
    @Override
    public User userUpdate(User user, HttpServletRequest request) {
        // 获取登陆用户，看看他的权限是什么
        User loginUser = (User) request.getSession().getAttribute(UserConstant.LOGIN_STATUS);
        if (loginUser == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "未登陆，请登陆后再操作");
        // 判断用户对象是否为空
        if (user == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户对象为空");
        // 如果用户不是管理员，那么只能修改自己数据中的「用户名、用户性别、用户头像、用户 Email」参数值
        if (loginUser.getUserRole().equals(UserConstant.USER_ROLE) || loginUser.getUserRole().equals(UserConstant.ADMIN_ROLE)) {
            // 如果只是用户，那么不能修改其他人的信息
            if (loginUser.getUserRole().equals(UserConstant.USER_ROLE) && !loginUser.getUserId().equals(user.getUserId()))
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法修改其他人的数据");
            String username = user.getUsername();
            Integer userSex = user.getUserSex();
            String userAvatar = user.getUserAvatar();
            String userEmail = user.getUserEmail();
            if (userSex != null && userSex != 0 && userSex != 1) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
            // 判断邮件格式是否正确
            if (StringUtils.isNotBlank(userEmail) && !userEmailVerify(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式有误，请重新输入");
            // 先从数据库获取数据
            User originalUser = this.getById(user.getUserId());
            if (originalUser == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "用户不存在");
            originalUser.setUsername(username);
            originalUser.setUserSex(userSex);
            originalUser.setUserAvatar(userAvatar);
            originalUser.setUserEmail(userEmail);
            // 如果是管理员，那么还需要处理「用户角色、用户状态」参数
            if (loginUser.getUserRole().equals(UserConstant.ADMIN_ROLE)) {
                String userRole = user.getUserRole();
                Integer userStatus = user.getUserStatus();
                if (userStatus == null || StringUtils.isBlank(userRole)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
                // 管理员不可以修改自己的身份和状态
                if (originalUser.getUserId().equals(loginUser.getUserId()) && (!userRole.equals(loginUser.getUserRole()) || !userStatus.equals(loginUser.getUserStatus()))) {
                    throw new BusinessException(ErrorCode.SYSTEM_ERROR, "拒绝修改管理员敏感信息!");
                }
                originalUser.setUserRole(userRole);
                originalUser.setUserStatus(userStatus);
            }
            boolean saveStatus = this.updateById(originalUser);
            if (!saveStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "数据库更新失败");
            return this.getSafetyUser(originalUser);
        }
        else throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户身份非法，无法更新");
    }

    /**
     * 判断登陆后的用户是否是管理员
     * @param request 原生 Servlet 请求对象
     * @return 是否是管理员
     */
    @Override
    public boolean isAdmin(HttpServletRequest request) {
        User user = (User) request.getSession().getAttribute(UserConstant.LOGIN_STATUS);
        return !Objects.isNull(user) && user.getUserRole().equals(UserConstant.ADMIN_ROLE);
    }

    /**
     * 用户信息脱敏
     * @return 返回脱敏的用户信息
     */
    @Override
    public User getSafetyUser(User user) {
        if (user == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "用户对象为空，无法脱敏");
        User safetyUser = new User();
        safetyUser.setUserId(user.getUserId());
        safetyUser.setUserAccount(user.getUserAccount());
        safetyUser.setUsername(user.getUsername());
        safetyUser.setUserSex(user.getUserSex());
        safetyUser.setUserAvatar(user.getUserAvatar());
        safetyUser.setUserEmail(user.getUserEmail());
        safetyUser.setUserRole(user.getUserRole());
        safetyUser.setUserStatus(user.getUserStatus());
        safetyUser.setInviteCode(user.getInviteCode());
        safetyUser.setCreateTime(user.getCreateTime());
        safetyUser.setUpdateTime(user.getUpdateTime());
        return safetyUser;
    }

    /**
     * 用户注销
     * @param request 原生 Servlet 请求对象
     */
    @Override
    public boolean userLogout(HttpServletRequest request) {
        request.getSession().removeAttribute(UserConstant.LOGIN_STATUS);
        return true;
    }

    /**
     * 用户账户验证接口
     * @param userAccount 用户账户
     * @return 判断账户是否合法
     */
    public boolean userAccountVerify(String userAccount) {
        String validAccountPattern = "[a-zA-Z][a-zA-Z0-9_]{5,}";
        Matcher matcher = Pattern.compile(validAccountPattern).matcher(userAccount);
        return matcher.find() && matcher.group().equals(userAccount);
    }

    public boolean userEmailVerify(String userEmail) {
        String validEmailPattern = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*";
        Matcher EmailMatcher = Pattern.compile(validEmailPattern).matcher(userEmail);
        return EmailMatcher.find() && EmailMatcher.group().equals(userEmail);
    }
}