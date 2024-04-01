-- auto-generated definition
create table user
(
    userId       bigint                                 not null comment '用户主键'
        primary key,
    userAccount  varchar(256)                           not null comment '用户账户',
    userPassword varchar(512)                           not null comment '用户账户密码',
    username     varchar(256)                           null comment '用户昵称',
    userSex      tinyint                                null comment '用户性别，0 表示女，1 表示男',
    userAvatar   varchar(1024)                          null comment '用户头像',
    userEmail    varchar(256)                           null comment '用户邮箱',
    userRole     varchar(256) default 'user'            not null comment '用户角色',
    userStatus   tinyint      default 1                 not null comment '账户状态，0 表示异常，1 表示正常',
    inviteCode   varchar(256)                           not null comment '邀请码',
    createTime   datetime     default CURRENT_TIMESTAMP not null comment '账户创建时间',
    updateTime   datetime     default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '账户最后更新时间',
    isDelete     tinyint      default 0                 not null comment '是否删除'
)
    comment '用户';

