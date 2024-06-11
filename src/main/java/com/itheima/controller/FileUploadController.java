package com.itheima.controller;

import com.itheima.pojo.Result;
import com.itheima.utils.AliOssUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

@RestController
public class FileUploadController {

    @PostMapping("/upload")
    public Result<String> upload(MultipartFile file) throws Exception {
        //把文件的内容存储到本地磁盘上
        final String originalFilename = file.getOriginalFilename();
        //保证文件的名字是唯一的,从而防止文件覆盖
        final String filename = UUID.randomUUID().toString()+originalFilename.substring(originalFilename.lastIndexOf("."));
        // 本地文件的目录
        // file.transferTo(new File("C:\\Users\\Administrator\\Desktop\\files\\"+filename));
        // return Result.success("图片URL地址。。。");

        // String url = AliOssUtil.uploadFile(filename,file.getInputStream());
        // return Result.success(url);
        return Result.success("https://avatars.githubusercontent.com/u/67958995?v=4");
    }
}
