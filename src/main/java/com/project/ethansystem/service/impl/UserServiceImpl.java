package com.project.ethansystem.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.project.ethansystem.common.ErrorCode;
import com.project.ethansystem.constant.UserConstant;
import com.project.ethansystem.exception.BusinessException;
import com.project.ethansystem.model.dto.user.UserRegisterRequest;
import com.project.ethansystem.model.dto.user.UserUpdateEmailRequest;
import com.project.ethansystem.model.entity.User;
import com.project.ethansystem.service.UserService;
import com.project.ethansystem.mapper.UserMapper;
import com.project.ethansystem.utils.EmailUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
* @author Ethan
* @description 针对表【user(用户)】的数据库操作Service实现
* @createDate 2024-03-15 00:17:30
*/
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    @Resource
    private EmailUtils emailUtils;

    // 验证码缓存
    private final Map<String, String> verificationCodeCache = new HashMap<>();

    /**
     * 用户注册
     * @param userAccount 用户账户
     * @param password 用户密码
     * @param verifyPassword 验证密码
     * @param verificationCode 用户邀请码
     * @return 返回用户账户 id
     */
    @Override
    public Long userRegister(String userAccount, String password, String verifyPassword, String userEmail, String verificationCode) {
        // 验证数据是否为空
        if (StringUtils.isAnyBlank(userAccount, password, verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        // 验证账户是否小于 5 位，密码是否小于 8 位，密码与验证密码是否相等
        if (userAccount.length() < 5 || password.length() < 8 || !password.equals(verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 判断账号是否有特殊字符
        if (!userAccountVerify(userAccount)) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "用户账户存在特殊字符");
        // 判断验证码是否正确
        verifyEmailCode(userEmail + UserConstant.REGISTER_EMAIL_TOKEN, verificationCode);
        // 判断邮件是否合法
        if (StringUtils.isNotBlank(userEmail) && !userEmailVerify(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误，请重新输入");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount).or().eq(User::getUserEmail, userEmail);
        User user = this.getOne(queryWrapper);
        if (user != null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户或邮箱已存在, 请重新输入");
        // 给用户输入的密码加密
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + password).getBytes());
        // 把数据保存在数据库中
        User finalUser = new User();
        finalUser.setUserAccount(userAccount);
        finalUser.setUserPassword(safetyPassword);
        finalUser.setUserEmail(userEmail);
        finalUser.setUsername(userAccount);     // 把用户昵称的默认值改成用户账户，防止前端显示出现问题
        boolean saveStatus = this.save(finalUser);
        if (!saveStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "数据库异常，请稍后再试");
        // 删除验证码
        verificationCodeCache.remove(userEmail + UserConstant.REGISTER_EMAIL_TOKEN);
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
        queryWrapper.eq(User::getUserAccount, userAccount).or().eq(User::getUserEmail, userEmail);
        User searchUser = this.getOne(queryWrapper);
        if (searchUser != null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户或邮箱已存在, 请重新输入");
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
        if (userAccount.length() < 5 || password.length() < 8)
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        // 判断账户中是否有特殊字符
        String validAccountPattern = "[a-zA-Z][a-zA-Z0-9_]{4,}";
        Matcher matcher = Pattern.compile(validAccountPattern).matcher(userAccount);
        if (!matcher.find() || !matcher.group().equals(userAccount))
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户账户存在特殊字符");
        // 把前端数据和数据库中的数据进行比较，判断是否匹配
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + password).getBytes());
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User targetUser = this.getOne(queryWrapper);
        if (targetUser == null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");    // 账户不存在
        if (!targetUser.getUserPassword().equals(safetyPassword))
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "密码错误");      // 密码错误
        // 判断用户状态是否正常，只有状态正常才可以登陆使用
        if (targetUser.getUserStatus().equals(UserConstant.USER_ABNORMAL))
            throw new BusinessException(ErrorCode.NULL_ERROR, "用户状态异常，请联系管理员处理");
        // 数据脱敏
        User safetyUser = getSafetyUser(targetUser);
        // 保存用户登陆状态
        request.getSession().setAttribute(UserConstant.LOGIN_STATUS, safetyUser);
        return safetyUser;
    }

    /**
     * 邮箱登陆
     * @param userEmail 用户邮箱
     * @param verificationCode 用户验证码
     * @param request 原生 Servlet 请求对象
     * @return 登陆的用户对象
     */
    @Override
    public User userLoginFromEmail(String userEmail, String verificationCode, HttpServletRequest request) {
        if (StringUtils.isAnyBlank(userEmail, verificationCode)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数不能为空！");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserEmail, userEmail);
        User targetUser = this.getOne(queryWrapper);
        if (Objects.isNull(targetUser)) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");
        // 检查验证码是否输入正确
        verifyEmailCode(targetUser.getUserAccount() + UserConstant.LOGIN_TOKEN, verificationCode);
        verificationCodeCache.remove(targetUser.getUserAccount() + UserConstant.LOGIN_TOKEN);
        // 用户数据脱敏
        User safetyUser = getSafetyUser(targetUser);
        // 保存用户登陆状态
        request.getSession().setAttribute(UserConstant.LOGIN_STATUS, safetyUser);
        return safetyUser;
    }

    /**
     * 根据条件筛选用户
     * @param user 满足条件的用户对象
     * @return 所有符合条件的用户集合
     */
    @Override
    public List<User> userSearch(User user) {
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(!Objects.isNull(user.getUserId()), User::getUserId, user.getUserId());
        queryWrapper.eq(StringUtils.isNotBlank(user.getUserAccount()), User::getUserAccount, user.getUserAccount());
        queryWrapper.like(StringUtils.isNotBlank(user.getUsername()), User::getUsername, user.getUsername());
        queryWrapper.eq(!Objects.isNull(user.getUserSex()), User::getUserSex, user.getUserSex());
        queryWrapper.eq(StringUtils.isNotBlank(user.getUserAvatar()), User::getUserAvatar, user.getUserAvatar());
        queryWrapper.eq(StringUtils.isNotBlank(user.getUserEmail()), User::getUserEmail, user.getUserEmail());
        queryWrapper.eq(StringUtils.isNotBlank(user.getUserRole()), User::getUserRole, user.getUserRole());
        queryWrapper.eq(!Objects.isNull(user.getUserStatus()), User::getUserStatus, user.getUserStatus());
        List<User> userList = this.list(queryWrapper);
        return userList.stream().map(this::getSafetyUser).toList();
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
        // 如果用户不是管理员，那么只能修改自己数据中的「用户名、用户性别、用户头像」参数值
        if (loginUser.getUserRole().equals(UserConstant.USER_ROLE) || loginUser.getUserRole().equals(UserConstant.ADMIN_ROLE)) {
            // 如果只是用户，那么不能修改其他人的信息
            if (loginUser.getUserRole().equals(UserConstant.USER_ROLE) && !loginUser.getUserId().equals(user.getUserId()))
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法修改其他人的数据");
            String username = user.getUsername();
            Integer userSex = user.getUserSex();
            String userAvatar = user.getUserAvatar();
            if (userSex != null && userSex != 0 && userSex != 1) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
            // 先从数据库获取数据
            User originalUser = this.getById(user.getUserId());
            if (originalUser == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "用户不存在");
            originalUser.setUsername(username);
            originalUser.setUserSex(userSex);
            originalUser.setUserAvatar(userAvatar);
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
     * 用户邮箱更新
     * @param userUpdateEmailRequest 用户更新邮箱所用的 DTO 对象
     * @param request 原生 Servlet 对象
     * @return 更新好之后的用户对象
     */
    @Override
    public User userUpdateEmail(UserUpdateEmailRequest userUpdateEmailRequest, HttpServletRequest request) {
        if (Objects.isNull(userUpdateEmailRequest) || Objects.isNull(request)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象不能为空");
        Long userId = userUpdateEmailRequest.getUserId();
        String userEmail = userUpdateEmailRequest.getUserEmail();
        String verificationCode = userUpdateEmailRequest.getVerificationCode();
        if (StringUtils.isAnyBlank(userEmail, verificationCode) || Objects.isNull(userId)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数不能为空");
        // 获取需要修改邮箱的用户对象
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserId, userId);
        User targetUser = this.getOne(queryWrapper);
        if (Objects.isNull(targetUser)) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");
        // 判断验证码是否正确
        verifyEmailCode(targetUser.getUserAccount() + UserConstant.RESET_EMAIL_TOKEN, verificationCode);
        // 如果用户的新邮箱和原来的邮箱一致，那么就直接返回
        if (targetUser.getUserEmail().equals(userEmail)) return getSafetyUser(targetUser);
        // 如果都不满足上面的情况，就更新邮件
        User updateUser = new User();
        updateUser.setUserId(userId);
        updateUser.setUserEmail(userEmail);
        boolean updateEmailStatus = this.updateById(updateUser);
        if (!updateEmailStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "系统异常, 请稍后再试");
        // 获取信息更新好之后的用户对象
        User safetyUser = this.getSafetyUser(this.getById(userId));
        // 删除验证码缓存
        verificationCodeCache.remove(safetyUser.getUserAccount() + UserConstant.RESET_EMAIL_TOKEN);
        return safetyUser;
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
    @Override
    public boolean userAccountVerify(String userAccount) {
        String validAccountPattern = "[a-zA-Z][a-zA-Z0-9_]{5,}";
        Matcher matcher = Pattern.compile(validAccountPattern).matcher(userAccount);
        return matcher.find() && matcher.group().equals(userAccount);
    }

    /**
     * 验证邮箱借口
     * @param userEmail 用户邮箱
     * @return 用户邮箱是否合法
     */
    @Override
    public boolean userEmailVerify(String userEmail) {
        String validEmailPattern = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*";
        Matcher EmailMatcher = Pattern.compile(validEmailPattern).matcher(userEmail);
        return EmailMatcher.find() && EmailMatcher.group().equals(userEmail);
    }

    /**
     * 给用户邮箱发送验证码
     * @param userEmail 用户邮箱
     * @param userAccount 用户账户令牌
     */
    @Override
    public void sendEmail(String userEmail, String userAccount) {
        if (StringUtils.isAnyBlank(userEmail, userAccount)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "输入的参数不能为空");
        String verificationCode = UUID.randomUUID().toString().substring(0, 6);
        try {
            emailUtils.sendMail(userEmail, verificationCode);
            verificationCodeCache.put(userAccount, verificationCode);       // 把验证码放入到缓存中，这样后面可以验证用户
        }
        catch (Exception exception) {
            log.error("消息发送失败，原因如下: " + exception.getMessage());
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, exception.getMessage());
        }
    }

    /**
     * 验证用户输入的验证码是否正确
     * @param userAccount 用户账户
     * @param verificationCode 用户输入的验证码
     */
    @Override
    public void verifyEmailCode(String userAccount, String verificationCode) {
        if (StringUtils.isAnyBlank(userAccount, verificationCode)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数不能为空!");
        // 如果验证码输入错误，就直接报错
        String verificationCodeFromCache = verificationCodeCache.getOrDefault(userAccount, null);
        if (verificationCodeFromCache == null) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "验证码已失效，请重新设置");
        if (!verificationCode.equals(verificationCodeFromCache)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码输入错误，请重新输入");
    }

    /**
     * 用户重置密码
     * @param userAccount 用户账户
     * @param userPassword 用户密码
     */
    @Override
    public void userResetPassword(String userAccount, String userPassword) {
        if (StringUtils.isAnyBlank(userAccount, userPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数不能为空!");
        // 构造修改密码后的新对象和条件对象
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + userPassword).getBytes());
        User user = new User();
        user.setUserPassword(safetyPassword);
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        boolean status = this.update(user, queryWrapper);
        if (!status) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "密码更新失败，请重试");
        // 如果更新成功，那么把验证码从缓存中删除，避免二次使用
        verificationCodeCache.remove(userAccount + UserConstant.RESET_PASSWORD_TOKEN);
    }

    /**
     * 判断用户是否已经存在
     * @param userRegisterRequest 用户注册的 DTO 对象
     * @return 用户是否存在
     */
    @Override
    public boolean userExists(@RequestBody UserRegisterRequest userRegisterRequest) {
        if (userRegisterRequest == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        String userEmail = userRegisterRequest.getUserEmail();
        String userAccount = userRegisterRequest.getUserAccount();
        String userPassword = userRegisterRequest.getUserPassword();
        String verifyPassword = userRegisterRequest.getVerifyPassword();
        if (StringUtils.isNoneBlank(userAccount, userPassword, verifyPassword)) {
            if (!userPassword.equals(verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次密码输入不一致");
            LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
            queryWrapper.eq(User::getUserAccount, userAccount);
            User user = this.getOne(queryWrapper);
            if (!Objects.isNull(user)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户账户已存在");
        }
        if (StringUtils.isNotBlank(userEmail)) {
            LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
            queryWrapper.eq(User::getUserEmail, userEmail);
            User user = this.getOne(queryWrapper);
            if (!Objects.isNull(user)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "该邮箱已被使用，请更换邮箱后尝试");
        }
        return false;
    }
}