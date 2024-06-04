# 大事件后端项目

## 一、项目起步



### 1. 创建springboot3项目

![image-20240601105057707](images\image-20240601105057707.png)

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

![image-20240601105555460](images\image-20240601105555460.png)

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

![image-20240601110512796](images\image-20240601110512796.png)

点击编译后，可以看到已经生成了getter setter这些

![image-20240601110704065](images\image-20240601110704065.png)

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

### 1.406 报错原因

![image-20240601120508231](images\image-20240601120508231.png)

报406 ，原因 `Result`类 没有加`@Data` 注解

![image-20240601120635911](images\image-20240601120635911.png)

加上即可

![image-20240601120719728](images\image-20240601120719728.png)

### 2.参数校验

![image-20240601121903443](images\image-20240601121903443.png)

![image-20240601121916110](images\image-20240601121916110.png)

使用 Spring Validation

> Spring 提供的一个参数校验框架,使用预定义的注解完成参数校验

![image-20240601121954312](images\image-20240601121954312.png)

这时候再次 发起注册的请求，且参数`username` 的值只有一位,会报500异常，并不是我们想要的

![image-20240601122302551](images\image-20240601122302551.png)

### 3. 全局异常处理器，捕获异常

![image-20240601122540155](images\image-20240601122540155.png)

```java
package com.itheima.exception;

import com.itheima.pojo.Result;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public Result handleException(Exception e){
        e.printStackTrace();
        return Result.error(StringUtils.hasLength(e.getMessage())? e.getMessage() : "操作失败");
    }
}
```

![image-20240601122635997](images\image-20240601122635997.png)

> Spring Validation 总结 
>
> 导入validation坐标
>
> 在参数上添加@Pattern注解,指定校验规则
>
> 在Controller类上添加@Validated注解
>
> 在全局异常处理器中处理参数校验失败的异常



## 三、登录接口

```java
@PostMapping("/login")
    public Result<String> login(@Pattern(regexp = "^\\S{5,16}$") String username, @Pattern(regexp = "^\\S{5,16}$") String password) {
        //根据用户名查询用户
        User loginUser = userService.findByUserName(username);
        //判断该用户是否存在
        if (loginUser == null) {
            return Result.error("用户名错误");
        }

        //判断密码是否正确  loginUser对象中的password是密文
        if (Md5Util.getMD5String(password).equals(loginUser.getPassword())) {

            return Result.success("jwt 令牌。。。");
        }
        return Result.error("密码错误");
    }
```



## 四、JWT令牌

![image-20240603091828087](images\image-20240603091828087.png)

> Header(头), 记录令牌类型和签名算法等
>
> PayLoad(载荷),携带自定义的信息
>
> Signature(签名),对头部和载荷进行加密计算得来



### 1. JWT 使用

> 引入java-jwt坐标
>
> 调用API生成或验证令牌

pom.xml 导入依赖

```xml
    <!--java-jwt坐标-->
    <dependency>
      <groupId>com.auth0</groupId>
      <artifactId>java-jwt</artifactId>
      <version>4.4.0</version>
    </dependency>

    <!--单元测试的坐标-->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
    </dependency>
```

 

jwt 测试类

```java
package com.itheima.bigevent;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTest {

    @Test
    public void testGen() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", 1);
        claims.put("username", "张三");
        //生成jwt的代码
        String token = JWT.create()
                .withClaim("user", claims)//添加载荷
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000*60*60*24))//添加过期时间
                .sign(Algorithm.HMAC256("itheima"));//指定算法,配置秘钥

        System.out.println(token);

    }

    @Test
    public void testParse() {
        //定义字符串,模拟用户传递过来的token
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxLCJ1c2VybmFtZSI6IuW8oOS4iSJ9LCJleHAiOjE3MTc0NjM2NTh9.QkaWOW0NUHhlUQZ0uq4LCSGM1Ta9mnjpA4UYCGKE8_I";

        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("itheima")).build();

        DecodedJWT decodedJWT = jwtVerifier.verify(token);//验证token,生成一个解析后的JWT对象
        Map<String, Claim> claims = decodedJWT.getClaims();
        System.out.println(claims.get("user"));

        //如果篡改了头部和载荷部分的数据,那么验证失败
        //如果秘钥改了,验证失败
        //token过期
    }
}

```



### 2.改造登录接口，返回JWT令牌

`JwtUtil`工具类

```java
package com.itheima.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.util.Date;
import java.util.Map;

public class JwtUtil {

    private static final String KEY = "itheima";
	
	//接收业务数据,生成token并返回
    public static String genToken(Map<String, Object> claims) {
        return JWT.create()
                .withClaim("claims", claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 12))
                .sign(Algorithm.HMAC256(KEY));
    }

	//接收token,验证token,并返回业务数据
    public static Map<String, Object> parseToken(String token) {
        return JWT.require(Algorithm.HMAC256(KEY))
                .build()
                .verify(token)
                .getClaim("claims")
                .asMap();
    }

}

```

`UserController.java`  的`login`接口

```java
 @PostMapping("/login")
    public Result<String> login(@Pattern(regexp = "^\\S{5,16}$") String username, @Pattern(regexp = "^\\S{5,16}$") String password) {
        //根据用户名查询用户
        User loginUser = userService.findByUserName(username);
        //判断该用户是否存在
        if (loginUser == null) {
            return Result.error("用户名错误");
        }

        //判断密码是否正确  loginUser对象中的password是密文
        if (Md5Util.getMD5String(password).equals(loginUser.getPassword())) {
            //登录成功
            Map<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            String token = JwtUtil.genToken(claims);
            return Result.success(token);
            // return Result.success("jwt 令牌。。。");
        }
        return Result.error("密码错误");
    }
```



### 3.登录认证

> 使用拦截器统一验证令牌
>
> 登录和注册接口需要放行



登录拦截器  `interceptors/LoginInterceptor.java`

```
package com.itheima.interceptors;


import com.itheima.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;


@Component
public class LoginInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 令牌验证
        String token = request.getHeader("Authorization");
        // 验证token
        try{
            Map<String, Object> claims = JwtUtil.parseToken(token);
            // 放行
            return true;
        }catch (Exception e){
            // http 响应状态码为401
            response.setStatus(401);
            // 不放行
            return false;
        }

    }

}

```



在 `WebMvcConfigurer` 中添加拦截器 `config/WebConfig.java`

```java
package com.itheima.config;

import com.itheima.interceptors.LoginInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Autowired
    private LoginInterceptor loginInterceptor;

    // 添加拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
       // 登录接口和注册接口不拦截
       registry.addInterceptor(loginInterceptor).excludePathPatterns("/user/login","/user/register");
    }
}

```



## 五、获取用户详细信息接口

```java
 /**
     * 获取用户详细信息
     * @param token 请求头Authorization 携带的token
     * @return 用户详细信息
     */
    @GetMapping("/userInfo")
    public Result<User> userInfo(@RequestHeader(name = "Authorization") String token){
        // 根据用户名查询用户
        Map<String, Object> map = JwtUtil.parseToken(token);
        String username =(String) map.get("username");

        User user = userService.findByUserName(username);
        return Result.success(user);
    }
```

![image-20240603103604743](images\image-20240603103604743.png)

可以看到密码也响应过来了。创建时间和更新时间也没有值

`user.java` 中添加如下：

```
  @JsonIgnore //让springmvc把当前对象转换成json字符串的时候,忽略password,最终的json字符串中就没有password这个属性了
  private String password;//密码
```

创建时间和更新时间也没有值，原因：数据库的字段是`create_time`,`update_time`, 而实体类是 `createTime`,`updateTime`

`application.yml` 文件修改如下：

```yaml
mybatis:
  configuration:
    map-underscore-to-camel-case: true #开启驼峰命名和下划线命名的自动转换
```

![image-20240603104315392](images\image-20240603104315392.png)

## 六、获取用户详细信息接口---ThreadLocal优化



`ThreadLocalUtil.java` 工具类

```
package com.itheima.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * ThreadLocal 工具类
 */
@SuppressWarnings("all")
public class ThreadLocalUtil {
    //提供ThreadLocal对象,
    private static final ThreadLocal THREAD_LOCAL = new ThreadLocal();

    //根据键获取值
    public static <T> T get(){
        return (T) THREAD_LOCAL.get();
    }
	
    //存储键值对
    public static void set(Object value){
        THREAD_LOCAL.set(value);
    }


    //清除ThreadLocal 防止内存泄漏
    public static void remove(){
        THREAD_LOCAL.remove();
    }
}

```

改造登录认证拦截器 `LoginInterceptor.java`

```java
package com.itheima.interceptors;


import com.itheima.utils.JwtUtil;
import com.itheima.utils.ThreadLocalUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;


@Component
public class LoginInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 令牌验证
        String token = request.getHeader("Authorization");
        // 验证token
        try{
            Map<String, Object> claims = JwtUtil.parseToken(token);
            //把业务数据存储到ThreadLocal中
            ThreadLocalUtil.set(claims);
            // 放行
            return true;
        }catch (Exception e){
            // http 响应状态码为401
            response.setStatus(401);
            // 不放行
            return false;
        }

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        //清空ThreadLocal中的数据
        ThreadLocalUtil.remove();
    }


}

```



改造 `UserController.java` 中的获取用户详细信息接口

```java

/**
     * 获取用户详细信息
     * @param token 请求头Authorization 携带的token
     * @return 用户详细信息
     */
    @GetMapping("/userInfo")
    public Result<User> userInfo(/*@RequestHeader(name = "Authorization") String token*/){
        /*// 根据用户名查询用户
        Map<String, Object> map = JwtUtil.parseToken(token);
        String username =(String) map.get("username");*/

        Map<String, Object> map = ThreadLocalUtil.get();
        String username = (String) map.get("username");

        User user = userService.findByUserName(username);
        return Result.success(user);
    }
```



> ThreadLocal小结
>
> 用来存取数据: set()/get()
>
> 使用ThreadLocal存储的数据, 线程安全
>
> 用完记得调用remove方法释放，防止内存泄漏



## 七、更新用户基本信息接口

```java
 /**
     * 更新用户基本信息
     * @param user
     * @return
     */
    @PutMapping("/update")
    public Result update(@RequestBody User user){
        userService.update(user);
        return Result.success();
    }



// 更新用户信息
void update(User user);

@Override
public void update(User user) {
    user.setUpdateTime(LocalDateTime.now()); //设置更新时间为当前时间
    userMapper.update(user);
}

// 更新
@Update("update user set nickname=#{nickname},email=#{email},update_time=#{updateTime} where id=#{id}")
void update(User user);
```

### 1.更新用户基本信息接口--参数校验

`User.java` 添加参数校验的注解

> @NotNull  值不能为null
>
> @NotEmpty 值不能为null,并且内容不为空
>
> @Email 满足邮箱格式

```java
 	@NotNull
    private Integer id;//主键ID    

	@NotEmpty
    @Pattern(regexp = "^\\S{1,10}$")
    private String nickname;//昵称


    @NotEmpty
    @Email
    private String email;//邮箱
```

改造 `UserController.java` 中的更新用户基本信息接口

```java
 /**
     * 更新用户基本信息
     * @param user
     * @return
     */
    @PutMapping("/update")
    public Result update(@RequestBody @Validated User user){
        userService.update(user);
        return Result.success();
    }
```

> 小结
>
> 实体类的成员变量上添加注解
>
> @NotNull
>
> @NotEmpty
>
> @Email
>
> 接口方法的实体参数上添加@Validated注解



## 八、更新用户头像接口

```java
 /**
     * 更新用户头像
     * @param avatarUrl 参数为URL地址值
     * @return
     */
    @PatchMapping("/updateAvatar")
    public Result updateAvatar(@RequestParam @URL String avatarUrl) {
        userService.updateAvatar(avatarUrl);
        return Result.success();
    }

// 更新用户头像
    void updateAvatar(String avatarUrl);

// 更新用户头像
@Override
public void updateAvatar(String avatarUrl) {
    Map<String,Object> map = ThreadLocalUtil.get();
    Integer id = (Integer) map.get("id");
    userMapper.updateAvatar(avatarUrl,id);
}


// 更新用户头像
    @Update("update user set user_pic=#{avatarUrl},update_time=now() where id=#{id}")
    void updateAvatar(String avatarUrl, Integer id);

```



## 九、更新用户密码接口

```java
/**
     * 更新用户密码
     * @param params
     * @return
     */
    @PatchMapping("/updatePwd")
    public Result updatePwd(@RequestBody Map<String, String> params) {
        //1.校验参数
        String oldPwd = params.get("old_pwd");
        String newPwd = params.get("new_pwd");
        String rePwd = params.get("re_pwd");

        if (!StringUtils.hasLength(oldPwd) || !StringUtils.hasLength(newPwd) || !StringUtils.hasLength(rePwd)) {
            return Result.error("缺少必要的参数");
        }

        //原密码是否正确
        //调用userService根据用户名拿到原密码,再和old_pwd比对
        Map<String,Object> map = ThreadLocalUtil.get();
        String username = (String) map.get("username");
        User loginUser = userService.findByUserName(username);
        if (!loginUser.getPassword().equals(Md5Util.getMD5String(oldPwd))){
            return Result.error("原密码填写不正确");
        }

        //newPwd和rePwd是否一样
        if (!rePwd.equals(newPwd)){
            return Result.error("两次填写的新密码不一样");
        }

        //2.调用service完成密码更新
        userService.updatePwd(newPwd);
        return Result.success();
    }


// 更新用户密码
    void updatePwd(String newPwd);
// 更新用户密码
    @Override
    public void updatePwd(String newPwd) {
        Map<String,Object> map = ThreadLocalUtil.get();
        Integer id = (Integer) map.get("id");
        userMapper.updatePwd(Md5Util.getMD5String(newPwd),id);
    }

  // 更新用户密码
    @Update("update user set password=#{md5String},update_time=now() where id=#{id}")
    void updatePwd(String md5String, Integer id);
```



## 十、文章分类接口-- 新增文章分类

`Category.java`

```java
package com.itheima.pojo;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class Category {
    private Integer id;//主键ID
    @NotEmpty
    private String categoryName;//分类名称
    @NotEmpty
    private String categoryAlias;//分类别名
    private Integer createUser;//创建人ID
    private LocalDateTime createTime;//创建时间
    private LocalDateTime updateTime;//更新时间
}
```

`CategoryController.java`

```java
package com.itheima.controller;


import com.itheima.pojo.Category;
import com.itheima.pojo.Result;
import com.itheima.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/category")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    @PostMapping
    public Result add(@RequestBody @Validated Category category){
        categoryService.add(category);
        return Result.success();
    }
}

```



`CategoryService.java`

```java
package com.itheima.service;

import com.itheima.pojo.Category;

public interface CategoryService {
    //新增分类
    void add(Category category);
}
```

`CategoryServiceImpl.java`

```java
package com.itheima.service.impl;

import com.itheima.mapper.CategoryMapper;
import com.itheima.pojo.Category;
import com.itheima.service.CategoryService;
import com.itheima.utils.ThreadLocalUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;


@Service
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    private CategoryMapper categoryMapper;
    @Override
    public void add(Category category) {
        //补充属性值
        category.setCreateTime(LocalDateTime.now());
        category.setUpdateTime(LocalDateTime.now());

        Map<String,Object> map = ThreadLocalUtil.get();
        Integer userId = (Integer) map.get("id");
        category.setCreateUser(userId);
        categoryMapper.add(category);
    }
}
```

`CategoryMapper.java`

```java
package com.itheima.mapper;

import com.itheima.pojo.Category;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CategoryMapper {

    //新增
    @Insert("insert into category(category_name,category_alias,create_user,create_time,update_time) " +
            "values(#{categoryName},#{categoryAlias},#{createUser},#{createTime},#{updateTime})")
    void add(Category category);
}
```





## 十一、文章分类接口-- 查询文章分类列表

```java
// 文章分类列表
    @GetMapping
    public Result<List<Category>> list(){
        List<Category> cs = categoryService.list();
        return Result.success(cs);
    }

// 分类列表
    List<Category> list();

@Override
    public List<Category> list() {
        Map<String,Object> map = ThreadLocalUtil.get();
        Integer userId = (Integer) map.get("id");
        return categoryMapper.list(userId);
    }

  //查询所有
    @Select("select * from category where create_user = #{userId}")
    List<Category> list(Integer userId);
```

