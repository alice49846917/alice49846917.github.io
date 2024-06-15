---
title: nestjs
date: 2024-05-11 14:25:13
tags:
---

# 项目地址
[https://github.com/dj49846917/vue3-nest-plat](https://github.com/dj49846917/vue3-nest-plat)

# 项目启动
1. 前端：
  ```
    cd frontend
    npm run dev
  ```
2. 后端：
  ```
    cd backend
    npm run start:dev
  ```
3. 启动数据库
  ```
    mysqlstart
  ```
4. 导入数据
  ```
    sql脚本在backend/sql/vben-book-dev(chapter9).sql
  ```

# 介绍
  * 使用vue3 + vite4 + ts + Nestjs + 无界微前端
  * 从0到1全栈开发一个管理后台项目
  * 业务功能包含框架搭建、登陆、权限、电子书管理等等
  * 无界微前端框架（基于webcomponent和iframe最新理念）

# 管理后端功能介绍：
  * 用户登录
  * 权限管理
    - 管理菜单
    - 管理用户
    - 管理角色
    - 管理权限
  * 图书管理
    - 图书列表查询
    - 图书上传
    - 图书阅读

# 技术架构
## 建站
  如何建站？
  * 域名：阿里云租用域名
  * 服务器：租用阿里云ECS服务器
  * web服务：nginx

## 开发
### 前端
  * 框架：vue-vben-admin 
    - 项目地址：https://github.com/vbenjs/vue-vben-admin?tab=readme-ov-file
  * 核心库：vue3全家桶（vue3+vueRouter4+pinia2）、vite4、ant-design-vue、windicss
  
### 后端
  * 框架：Nodejs + Nestjs
    - 依赖注入
    - Restful API
    - JWT权鉴
    - CORS跨域
    - ORM模型
  * 数据库：MySQL

# 前端部分
## 项目搭建
  ```
    git clone https://github.com/vbenjs/vue-vben-admin.git
  ```
  * 安装pnpm
    ```
      npm install -g pnpm
      pnpm install
    ```
  * 启动
    ```
      npm run dev
    ```

# 后端部分
## 项目搭建
  ```
    npm i -g @nestjs/cli
    nest new project-name
  ```

## 简单例子
  最简单的crud，可以切换到basic-demo分支看
  1. 在app.controller.ts中：
  ```
    import { Body, Controller, Delete, Get, Post, Put } from '@nestjs/common';
    import { AppService } from './app.service';

    export type AddParamsType = {
      name: string,
      age: number
    }

    @Controller()
    export class AppController {
      constructor(private readonly appService: AppService) { }
      @Get("/data/list")
      getAllData(): string {
        return this.appService.getAllData();
      }

      @Post("/data/add")
      addData(@Body() body:AddParamsType): string {
        return this.appService.addData(body);
      }

      @Put("/data/update")
      updateData(@Body() body:AddParamsType): string {
        return this.appService.updateData(body);
      }

      @Delete("/data/del")
      delData(@Body() body: {id: string}): string {
        return this.appService.delData(body);
      }
    }
  ```
  2. 在app.service.ts中：
  ```
    import { Injectable } from '@nestjs/common';
    import { AddParamsType } from './app.controller';

    @Injectable()
    export class AppService {
      getData(): string {
        return "get Data";
      }

      getAllData(): string {
        return "All Data"
      }

      addData(params: AddParamsType): string {
        return "add Data" + JSON.stringify(params);
      }

      updateData(params: AddParamsType): string {
        return "update Data" + JSON.stringify(params);
      }

      delData(params: {id: string}): string {
        return `删除成功id: ${params.id}`;
      }
    }
  ```
  3. 在postman中输入localhost:3030/data/add, body中填入name和age就能调试
  
## 后端功能点
![后端功能](/images/vue3Nest/back-func.png)

## 创建user模块
  执行命令：
  ```
    nest g module user
    nest g controller user
  ```
  1. 执行之后，系统会在src下面创建user文件夹和user.contoller.ts、user.module.ts，并且在app.module.ts中自动引入
  2. 简单写入以下代码，输入localhost:3000/user/list页面就会响应内容
    ```
      import { Controller, Get } from '@nestjs/common';

      @Controller('user')
      export class UserController {        
        @Get("/list")
        getData():string {
          return "aaaa"
        }
      }
    ```

## 创建auth模块（同上）

## 创建modules和controllers文件夹
  将user.module.ts放到modules/user文件夹下，user.controller.ts放到controllers/user文件夹下（auth同上）

## mysql数据库搭建
- 安装教学：
windows安装：[https://blog.csdn.net/rbx508780/article/details/127176754](https://blog.csdn.net/rbx508780/article/details/127176754)
mac安装：[https://blog.csdn.net/bitat/article/details/134065466](https://blog.csdn.net/bitat/article/details/134065466)
- 官网下载：
[https://dev.mysql.com/downloads/](https://dev.mysql.com/downloads/)
- 报错解决方案:
[https://blog.csdn.net/pansanday/article/details/82684776](https://blog.csdn.net/pansanday/article/details/82684776)
[https://www.cnblogs.com/timetellu/p/12808773.html](https://www.cnblogs.com/timetellu/p/12808773.html)

- 启动命令：
  ```
    # 启动
    mysqlstart

    # 关闭
    mysqlstop

    # 重启
    mysqlrestart
  ```

## 下载Navcat
  * 官网下载：[https://www.navicat.com.cn/download/navicat-for-mysql](https://www.navicat.com.cn/download/navicat-for-mysql)

### 新建数据库
  1. 打开navcat，点击新建连接，输入密码保存
  2. 创建vben-book-dev数据库，字符集选`utf8mb3`,排序规则选`utf8mb3_general_ci`
  3. 导入sql文件，地址在backend/sql/vben-book-dev(chapter9).sql
   
## 集成TypeORM连接池
  1. 安装依赖
    ```
      cd backend
      npm install --save @nestjs/typeorm typeorm mysql2
    ```
  
  2. 安装过程完成后，我们可以将 `TypeOrmModule` 导入到根 `AppModule` 中
    ```
      import { TypeOrmModule } from '@nestjs/typeorm';

      @Module({
        imports: [ 
          TypeOrmModule.forRoot({
            type: "mysql",
            host: "localhost",
            port: 3306,
            username: "root",
            password: "admin123456",
            database: "vben-book-dev",
            synchronize: true
          })
        ],
        ...
      })
    ```

{% note danger %}
  注意: 设置 synchronize: true 不应在生产中使用 - 否则你可能会丢失生产数据。
{% endnote %}

  3. 创建实体entity，用于与数据库字段做一一映射
    * 创建user.entity.ts，对应数据库的admin_user表
      ```
        import { Column, Entity, PrimaryGeneratedColumn, Unique } from "typeorm";

        @Entity("admin_user") // 对应admin_user表
        export class User {
          @PrimaryGeneratedColumn()  // 自增
          id: number;
          
          @Column()   // 列
          @Unique(["username"]) // 唯一值
          username: string;
          
          @Column()
          password: string;

          @Column()
          role: string;

          @Column()
          nickname: string;

          @Column()
          active: number;

          @Column()
          avatar: string;
        }
      ```

  4. 连接admin_user表
     * 在modules/user/user.module.ts中，引入user的entity
      ```
        import { User } from 'src/entity/user.entity';

        @Module({
          imports: [TypeOrmModule.forFeature([User])],
          ...
        })
      ```
     * 创建user的service用来处理contoller的逻辑
      ```
        在src下新建service/user/user.service/ts
      ```
     * 在user.module.tsx中引入
      ```
        import { UserService } from 'src/service/user/user.service';

        @Module({
          imports: [TypeOrmModule.forFeature([User])],
          controllers: [UserController],
          providers: [UserService]
        })
        export class UserModule {}

      ```
     * 在src/service/user/user.service.ts中写入查询单条数据的方法
      ```
        import { Injectable } from "@nestjs/common";
        import { InjectRepository } from "@nestjs/typeorm";
        import { User } from "src/entity/user.entity";
        import { Repository } from "typeorm";

        @Injectable()
        export class UserService {
          // 固定写法，通过typeorm获取admin_user的表数据
          constructor(
            @InjectRepository(User)
            // userTable这个名称可以随便取
            private readonly userTable: Repository<User>
          ) { }

          // 查询单条信息
          findOne(id: number): Promise<User> {
            return this.userTable.findOneBy({ id });
          }
        }
      ```
     * 在src/controllers/user/user.controller.ts中引入findOne方法
      ```
        import { Controller, Get, Param, ParseIntPipe } from '@nestjs/common';
        import { UserService } from 'src/service/user/user.service';

        @Controller('user')
        export class UserController {
          constructor(private readonly UserService: UserService){}

          @Get("/:id")
          // ParseIntPipe表示将id转换为int类型
          getData(@Param("id", ParseIntPipe) id: number) {
            return this.UserService.findOne(id);
          }
        }
      ```
  5. 在postman中测试findOne接口，访问http://localhost:3000/user/10
    ```
      结果在node端报错了
      EntityMetadataNotFoundError: No metadata for "User" was found.

      解决办法：
      在app.module.ts的TypeOrmModule中，添加 autoLoadEntities: true

      @Module({
        imports: [
          UserModule, 
          AuthModule, 
          TypeOrmModule.forRoot({
            type: "mysql",
            host: "localhost",
            port: 3306,
            username: "root",
            password: "admin123456",
            database: "vben-book-dev",
            autoLoadEntities: true
            // synchronize: true
          })
        ],
        controllers: [AppController],
        providers: [AppService],
      })
    ```
  6. 查询所有数据
    ```
      # src/service/user/user.service.ts中

      // 查询所有信息
      findAll(): Promise<User[]> {
        return this.userTable.find();
      }

      # src/controllers/user/user.controller.ts中

      @Get()
      // ParseIntPipe表示将id转换为int类型
      getList() {
        return this.UserService.findAll();
      }
    ```
  
  7. 新增
    ```
      # src/type/index.ts中
      
      export type UserDto = {
        username: string;
        password: string;
        role: string;
        nickname: string;
        active: number;
        avatar: string;
      }

      # src/service/user/user.service.ts中

      // 新增
      createData(params: UserDto): Promise<User> {
        let user = new User();
        user = {
          ...user,
          ...params,
          active: 1
        }
        return this.userTable.save(user);
      }

      # src/controllers/user/user.controller.ts中

      @Post("/add")
      add(@Body() body: UserDto) {
        return this.UserService.createData(body);
      }
    ```

  8. 删除
    ```
      # src/service/user/user.service.ts中

      // 删除
      delData(id: number): Promise<DeleteResult> {
        return this.userTable.delete(id);
      }

      # src/controllers/user/user.controller.ts中

      @Delete("/:id")
      delData(@Param("id", ParseIntPipe) id: number) {
        return this.UserService.delData(id);
      }
    ```

  9. 更新
    ```
      # src/type/index.ts

      export type UserTable = UserDto & {
        id: number
      }

      # src/service/user/user.service.ts中

      // 修改数据
      async updateData(params: UserTable): Promise<User> {
        const user = await this.findOne(params.id);
        const newUser = JSON.parse(JSON.stringify(params));
        if(newUser.id) {
          delete newUser.id
        }
        this.userTable.merge(user, newUser);
        return this.userTable.save(user);
      }

      # src/controllers/user/user.controller.ts中

      @Put("/update")
      update(@Body() body: UserTable) {
        return this.UserService.updateData(body);
      }
    ```

# 登录功能开发
## 后端开发
### 创建请求守卫
1. 在src/service/auth/auth.service.ts写入
  ```
    import { Injectable } from "@nestjs/common";

    @Injectable()
    export class AuthService {
      
    }
  ```
2. 在src/guard/auth.guard.ts创建请求守卫
  ```
    import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
    import { Observable } from "rxjs";

    @Injectable()
    export class AuthGuard implements CanActivate {
      canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        return undefined;
      }
    }
  ```

3. 在src/modules/auth/auth.module.ts中的providers中引入上面的文件
  ```
    import { Module } from '@nestjs/common';
    import { AuthController } from '../../controllers/auth/auth.controller';
    import { AuthService } from 'src/service/auth/auth.service';
    import { APP_GUARD } from '@nestjs/core';
    import { AuthGuard } from 'src/guard/auth/auth.guard';

    @Module({
      controllers: [AuthController],
      providers: [AuthService, {
        provide: APP_GUARD,
        useClass: AuthGuard
      }]
    })
    export class AuthModule {}
  ```
> 这个时候在postman get请求访问http://localhost:3000/user就会包403

4. 绕开guard，使请求成功，在src/guard/auth/public.decorator.ts中写入：
  ```
    import { SetMetadata } from "@nestjs/common";

    export const IS_PUBLIC_KEY = 'isPublic';
    export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
  ```
5. 修改src/guard/auth/auth.guard.ts
  ```
    import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
    import { Reflector } from "@nestjs/core";
    import { Observable } from "rxjs";
    import { IS_PUBLIC_KEY } from "./public.decorator";

    @Injectable()
    export class AuthGuard implements CanActivate {
      constructor(private reflector: Reflector) {}
      canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const isPublic = this.reflector.getAllAndOverride(IS_PUBLIC_KEY, [
          context.getHandler(),
          context.getClass()
        ]);
        if(isPublic) {
          return true;
        }
        return undefined;
      }
    }
  ```

6. 在src/contollers/auth/auth.controller.ts中创建一个login方法
  ```
    import { Controller, Post } from '@nestjs/common';
    import { Public } from 'src/guard/auth/public.decorator';

    @Controller('auth')
    export class AuthController {
        @Public()
        @Post("login")
        login() {
            return "auth";
        }
    }
  ```
> 再次使用postman post http://localhost:3000/auth/login，返回auth，不再报403

### 登录的链路调用
1. 在user.userservice.ts中编写findByUsername的方法
  ```
    // 根据username查询
    findByUsername(username: string):Promise<User> {
      return this.userTable.findOneBy({username})
    }
  ```
2. 在user.module.ts中导出UserService
  ```
    import { UserService } from 'src/service/user/user.service';

    @Module({
      ...
      exports: [UserService]
    })
    export class UserModule {}
  ```
3. 在auth.module.ts中引入UserModule
  ```
    import { UserModule } from '../user/user.module';

    @Module({
      imports: [UserModule],
      ...
    })
    export class AuthModule {}
  ```
4. 在auth.service.ts中编写login方法，调用userSerive的findByUsername方法
  ```
    import { Injectable } from "@nestjs/common";
    import { UserService } from "../user/user.service";

    @Injectable()
    export class AuthService {
      constructor(
        private userService: UserService
      ){}

      async login(username, password) {
        const user = await this.userService.findByUsername(username);
        console.log("user", user);
      } 
    }
  ```
5. 在auth.controller.ts中编写login方法调用authService的login
  ```
    import { Body, Controller, Post } from '@nestjs/common';
    import { Public } from 'src/guard/auth/public.decorator';
    import { AuthService } from 'src/service/auth/auth.service';

    @Controller('auth')
    export class AuthController {
      constructor(
        private authService: AuthService
      ) {}
      @Public()
      @Post("login")
      async login(@Body() params) {
        await this.authService.login(params.username, params.password)
        return "auth";
      }
    }
  ```

6. 测试：在postman中测试post接口：http://localhost:3000/auth/login, 参数: {username: admin, password: 123456}  并不报错

7. 使用md5加密密码
  ```
    pnpm add md5
    pnpm add -D @types/md5

    # 在auth.service.ts中

    import { Injectable, UnauthorizedException } from "@nestjs/common";
    import { UserService } from "../user/user.service";
    import * as md5 from 'md5'

    @Injectable()
    export class AuthService {
      constructor(
        private userService: UserService
      ){}

      async login(username, password) {
        const user = await this.userService.findByUsername(username);
        const parsePas = md5(password).toUpperCase();
        if(user.password !== parsePas) {
          throw new UnauthorizedException();
        }
      } 
    }
  ```

### 使用JWT生成token
1. 安装@nestjs/jwt包
  ```
    pnpm add @nestjs/jwt
  ```
2. 在auth.module.ts中引入jwt模块
  ```
    import { JwtModule } from '@nestjs/jwt';

    @Module({
      imports: [
        ...
        JwtModule.register({
          global: true,
          secret: 'abcdefg', // 私钥(约定好)
          signOptions: { 
            expiresIn: 24 * 60 * 60 + 's' // 过期时间
          }
        })
      ],
      ...
    })
    export class AuthModule { }
  ```

3. 在auth.service.ts中生成token
  ```
    import { Injectable, UnauthorizedException } from "@nestjs/common";
    import { UserService } from "../user/user.service";
    import * as md5 from 'md5'
    import { JwtService } from "@nestjs/jwt";

    @Injectable()
    export class AuthService {
      constructor(
        private userService: UserService,
        private jwtService: JwtService
      ){}

      async login(username, password) {
        const user = await this.userService.findByUsername(username);
        const parsePas = md5(password).toUpperCase();
        if(user.password !== parsePas) {
          throw new UnauthorizedException();
        }
        // 生成token的数据
        const payload = {
          username: user.username,
          userid: user.id
        }
        return {
          token: await this.jwtService.signAsync(payload)
        }
      } 
    }
  ```

4. 在utils/index.ts中封装请求成功和失败的两个公共方法
  ```
    export function success(data, msg) {
      return {
        code: 0,
        data,
        msg
      }
    }

    export function error(msg) {
      return {
        code: -1,
        msg
      }
    }
  ```

5. 在auth.controller.ts中修改login方法
  ```
    import { Body, Controller, Post } from '@nestjs/common';
    import { Public } from 'src/guard/auth/public.decorator';
    import { AuthService } from 'src/service/auth/auth.service';
    import { error, success } from 'src/utils';

    @Controller('auth')
    export class AuthController {
      constructor(
        private authService: AuthService
      ) {}
      @Public()
      @Post("login")
      login(@Body() params) {
        return this.authService.login(params.username, params.password)
        .then((data)=>success(data, '登录成功'))
        .catch(err=>error(err.message))
      }
    }
  ```

6. 测试：postman输入post接口：http://localhost:3000/auth/login
  ```
    # 参数：{username: admin, password: 123456}
    # 输出：
    {
      "code": 0,
      "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcmlkIjoxMiwiaWF0IjoxNzE4MzU4NDQwLCJleHAiOjE3MTg0NDQ4NDB9.4q0tpNUP_481eTiejxuKGxpz0zWtDwUJuWZ9y72BJkg"
      },
      "msg": "登录成功"
    }

    # 参数：{username: admin, password: 1234567}
    # 输出：
    {
      "code": -1,
      "msg": "Unauthorized"
    }
  ```
7. 分支7.5jwt

## 前后端连调
### 前端部分
1. 找到src/api/sys/user.ts， 修改loginApi的url
  ```
    enum Api {
      Login = '/auth/login',  
      ...
    }
  ```

2. 修改.env.development文件中的VITE_GLOB_API_URL
  ```
    # Basic interface address SPA
    VITE_GLOB_API_URL = http://localhost:3000
  ```

3. 修改src/views/sys/login/LoginForm.vue的默认账号密码
  ```
    const formData = reactive({
      account: 'admin',
      password: '123456',
    });
  ```
4. 启动前端，点击登录，报跨域
  
### 后端部分
1.  找到src/main.ts，添加cors
  ```
    import { NestFactory } from '@nestjs/core';
    import { AppModule } from './app.module';

    async function bootstrap() {
      const app = await NestFactory.create(AppModule, {cors: true});
      await app.listen(3000);
    }
    bootstrap();
  ```
2. 启动后端

### 测试
  ```
    # 点击登录
    # 输出：
    {
      "code": 0,
      "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcmlkIjoxMiwiaWF0IjoxNzE4MzYzODU4LCJleHAiOjE3MTg0NTAyNTh9.gMa8O-xFXYkvtU-4HNlyrX5e-HFksELYT2vSNe7djSk"
      },
      "msg": "登录成功"
    }
  ```

## 完善登录流程
1. 目前启动前端点击登录会报错，找到frontend/src/utils/http/axios/index.ts里面的transformResponseHook方法
  ```
    ...
    const { code, result, message } = data;
  ```

2. 修改backend/src/utils/index.ts中的success和error方法的返回，与前端对应
  ```
    export function success(result, message) {
      return {
        code: 0,
        result,
        message
      }
    }

    export function error(message) {
      return {
        code: -1,
        message
      }
    }
  ```
3. 测试：成功

## 开发查询用户信息接口
1. 新建src/contant/index.ts，存放secret
  ```
    # 值可以随便定义
    export const JWT_SECRET_KEY = "abcdefg";
  ```
2. 在guard/auth/auth.guard.ts拦截器中编写解析token的方法
  ```
    import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
    import { Reflector } from "@nestjs/core";
    import { IS_PUBLIC_KEY } from "./public.decorator";
    import { JwtService } from "@nestjs/jwt";
    import { JWT_SECRET_KEY } from "src/constant";

    @Injectable()
    export class AuthGuard implements CanActivate {
      constructor(
        private reflector: Reflector,
        private jwtService: JwtService
      ) {}
      async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride(IS_PUBLIC_KEY, [
          context.getHandler(),
          context.getClass()
        ]);
        if(isPublic) {
          return true;
        }
        const request = context.switchToHttp().getRequest();
        const token = extractTokenFromHeader(request);
        if(!token) {
          throw new UnauthorizedException();
        }
        try {
          // 解析token
          const payload = await this.jwtService.verifyAsync(token, {
            secret: JWT_SECRET_KEY
          })
          request['user'] = payload;
        } catch (error) {
          throw new UnauthorizedException();
        }
        return true;
      }
    }

    // 解析token
    function extractTokenFromHeader(request: any): string | undefined {
      const [type, token] = request.headers.authorization?.split(' ') ?? [];
      return type === 'Bearer' ? token : undefined;
    }
  ```
3. 修改auth.module.ts中secret
  ```
    import { JWT_SECRET_KEY } from 'src/constant';
    
    @Module({
      imports: [
        UserModule,
        JwtModule.register({
          global: true,
          secret: JWT_SECRET_KEY, // 私钥(约定好)
          signOptions: { 
            expiresIn: 24 * 60 * 60 + 's' // 过期时间
          }
        })
      ],
      ...
    })
  ```
4. 在utils.ts中使用wrapperResponse再封装下返回的请求
  ```
    export function success(result: any, message: string) {
      return {
        code: 0,
        result,
        message
      }
    }

    export function error(message: string) {
      return {
        code: -1,
        message
      }
    }
    export function wrapperResponse(p: Promise<any>, msg: string){
      return p.then((res) => {
        return success(res, msg)
      }).catch((err) => {
        return error(err.message)
      })
    }
  ```

5. 在user.controller.ts中编写getUserByToken方法
  ```
    import { Controller, Get, Req } from '@nestjs/common';
    import { UserService } from 'src/service/user/user.service';
    import { wrapperResponse } from 'src/utils';

    @Controller('user')
    export class UserController {
      constructor(private readonly UserService: UserService) { }

      @Get("info")
      getUserByToken(@Req() request) {
        // 前面gurad使用了request['user']=payload,这里就可以直接用request.user拿到token解析后的userinfo
        return wrapperResponse(this.UserService.findByUsername(request.user.username), "获取用户信息成功");
      }
      ...
    }
  ```
6. 同样的修改下auth.controller.ts中的login
  ```
    import { Body, Controller, Post } from '@nestjs/common';
    import { Public } from 'src/guard/auth/public.decorator';
    import { AuthService } from 'src/service/auth/auth.service';
    import { wrapperResponse } from 'src/utils';

    @Controller('auth')
    export class AuthController {
      constructor(
        private authService: AuthService
      ) {}
      @Public()
      @Post("login")
      login(@Body() params) {
        return wrapperResponse(this.authService.login(params.username, params.password), "登录成功")
      }
    }
  ```

7. 测试：postman get接口：http://localhost:3000/user/info，配置环境变量Authorization
  ```
    # 输出
    {
      "code": 0,
      "result": {
        "id": 12,
        "username": "admin",
        "password": "E10ADC3949BA59ABBE56E057F20F883E",
        "role": "[\"super\"]",
        "nickname": "adminUser",
        "active": 1,
        "avatar": "https://www.youbaobao.xyz/mpvue-res/logo.jpg"
      },
      "message": "获取用户信息成功"
    }
  ```

## userInfo接口前后端连调
1. 修改src/api/sys/user.ts中，getUserInfo的url
  ```
    enum Api {
      ...
      GetUserInfo = '/user/info',
      ...
    }
  ```
2. 在src/utils/http/axios/index.ts中修改createAxios
  ```
    function createAxios(opt?: Partial<CreateAxiosOptions>) {
      return new VAxios(
        // 深度合并
        deepMerge(
          {
            ...
            authenticationScheme: 'Bearer',
            ...
          },
          ...
        ),
      );
    }
  ```
> 测试 点击登录按钮，最后成功跳转到首页