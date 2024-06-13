package com.itheima.controller;

import com.itheima.pojo.Result;
import com.itheima.utils.AliOssUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.UUID;

@RestController
public class FileUploadController {

    // @PostMapping("/upload")
    // public Result<String> upload(MultipartFile file) throws Exception {
    //     //把文件的内容存储到本地磁盘上
    //     final String originalFilename = file.getOriginalFilename();
    //     //保证文件的名字是唯一的,从而防止文件覆盖
    //     final String filename = UUID.randomUUID().toString()+originalFilename.substring(originalFilename.lastIndexOf("."));
    //     // 本地文件的目录
    //     // file.transferTo(new File("C:\\Users\\Administrator\\Desktop\\files\\"+filename));
    //     // return Result.success("图片URL地址。。。");
    //
    //     // String url = AliOssUtil.uploadFile(filename,file.getInputStream());
    //     // return Result.success(url);
    //     return Result.success("https://avatars.githubusercontent.com/u/67958995?v=4");
    // }


    // 生成base64 字符串
    @PostMapping("/upload")
    public Result<String> upload(MultipartFile file) throws Exception {
        // 从 MultipartFile 获取输入流
        InputStream inputStream = file.getInputStream();

        // 将输入流转换为字节数组
        byte[] bytes = inputStream.readAllBytes();

        // 将字节数组编码为 Base64 字符串
        String base64String = Base64.getEncoder().encodeToString(bytes);

        // 关闭输入流
        inputStream.close();

        // 返回 Base64 字符串
        return Result.success(base64String);
    }
}
