# 大事件后端项目

## 一、项目起步



### 1. 创建springboot3项目

![image-20240601105057707](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601105057707.png)

### 2.执行sql

```sql
-- 创建数据库
create database big_event;

-- 使用数据库
use big_event;

-- 用户表
create table user (
                      id int unsigned primary key auto_increment comment 'ID',
                      username varchar(20) not null unique comment '用户名',
                      password varchar(32)  comment '密码',
                      nickname varchar(10)  default '' comment '昵称',
                      email varchar(128) default '' comment '邮箱',
                      user_pic varchar(128) default '' comment '头像',
                      create_time datetime not null comment '创建时间',
                      update_time datetime not null comment '修改时间'
) comment '用户表';

-- 分类表
create table category(
                         id int unsigned primary key auto_increment comment 'ID',
                         category_name varchar(32) not null comment '分类名称',
                         category_alias varchar(32) not null comment '分类别名',
                         create_user int unsigned not null comment '创建人ID',
                         create_time datetime not null comment '创建时间',
                         update_time datetime not null comment '修改时间',
                         constraint fk_category_user foreign key (create_user) references user(id) -- 外键约束
);

-- 文章表
create table article(
                        id int unsigned primary key auto_increment comment 'ID',
                        title varchar(30) not null comment '文章标题',
                        content varchar(10000) not null comment '文章内容',
                        cover_img varchar(128) not null  comment '文章封面',
                        state varchar(3) default '草稿' comment '文章状态: 只能是[已发布] 或者 [草稿]',
                        category_id int unsigned comment '文章分类ID',
                        create_user int unsigned not null comment '创建人ID',
                        create_time datetime not null comment '创建时间',
                        update_time datetime not null comment '修改时间',
                        constraint fk_article_category foreign key (category_id) references category(id),-- 外键约束
                        constraint fk_article_user foreign key (create_user) references user(id) -- 外键约束
)
```

### 3. 在pom.xml中 引入依赖

```xml
        <!--web依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!--mybatis依赖-->
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>3.0.0</version>
        </dependency>

        <!--mysql驱动依赖-->
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
        </dependency>
```

### 4.创建需要的目录，并编写对应的实体类

![image-20240601105555460](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601105555460.png)

### 5. 在application.yml 文件中 编写数据连接配置

```yaml
spring:
  application:
    name: big-event
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/big_event
    username: root
    password: root
```



### 6.在pom.xml 中引入lombok依赖

>  lombok  在编译阶段,为实体类自动生成setter  getter toString
>  pom文件中引入依赖   在实体类上添加注解

```xml
<!--lombok依赖-->
    <dependency>
      <groupId>org.projectlombok</groupId>
      <artifactId>lombok</artifactId>
    </dependency>
```

在pojo文件下的实体类中添加`@Data` 就行

![image-20240601110512796](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601110512796.png)

点击编译后，可以看到已经生成了getter setter这些

![image-20240601110704065](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601110704065.png)

### 7.编写Result 类，用来统一返回接口数据,放在pojo文件夹中

```
package com.itheima.pojo;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

//统一响应结果
@NoArgsConstructor
@AllArgsConstructor
public class Result<T> {
    private Integer code;//业务状态码  0-成功  1-失败
    private String message;//提示信息
    private T data;//响应数据

    //快速返回操作成功响应结果(带响应数据)
    public static <E> Result<E> success(E data) {
        return new Result<>(0, "操作成功", data);
    }

    //快速返回操作成功响应结果
    public static Result success() {
        return new Result(0, "操作成功", null);
    }

    public static Result error(String message) {
        return new Result(1, message, null);
    }
}

```



## 二、注册接口

![image-20240601120508231](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601120508231.png)

报406 ，原因 `Result`类 没有加`@Data` 注解

![image-20240601120635911](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601120635911.png)

加上即可

![image-20240601120719728](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240601120719728.png)
