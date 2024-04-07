### 1. 概述

此项目实现了日常学习中常用的几个信息安全工具，并为它们统一设计了使用界面（vue2）

除此之外我们结合此前的项目经历实现了Linux下的包过滤防火墙，可以按照用户的实际需求灵活的配置数据报过滤服务

<font color="red">写在前面：由于收尾工作较为仓促，所以可能会有一些配置上的小问题未被发现。如果您发现有哪些功能无法使用，大概率是系统环境配置问题，请您联系我们组长</font>（**张瀚文**）<font color="red">，他会给您详细解答。谢谢！</font>

### 2. 信息安全工具介绍

我们项目的重点展示内容在**前后端模块**

前三个小模块中的`start.sh`脚本是在windows下撰写的，所以可能在linux下无法直接运行（由于windows下的换行符'\r'无法在linux下被正确识别），需要使用`dos2unix`将其转换一下格式，例如：

```shell
dos2unix start.sh
```

#### 2.1 加密工具

加密模块所在目录为`Cryptography`，其中包括代码、图片资源等。加密功能包括对称加解密、非对称加解密、数字签名、信息校验码、信息隐写等

单独启动该功能的方法为执行`start.sh`脚本

#### 2.2 SNMP工具

SNMP工具所在目录为`SNMP`，其中包括代码、图片资源等。SNMP工具包括GET、SET、监听trap包和系统状态检测功能

单独启动该功能的方法为执行`start.sh`脚本

#### 2.3 Sniffer工具

Sniffer工具所在目录为`Sniffer`，其中包括代码

单独启动该功能的方法为执行`start.sh`脚本

#### 2.4 前后端模块

前后端实现的代码位于`platform`目录，其中前端代码位于`frontend`子目录中，后端代码位于`backend`子目录中，python服务器函数位于`pythonserver`目录中

建议在进行下述操作前进行docker换源：

1. 首先创建`daemon.json`文件

```shell
sudo vim /etc/docker/daemon.json
```

2. 将下述内容复制进去

```json
{
    "registry-mirrors": [
        "https://registry.docker-cn.com",
        "http://hub-mirror.c.163.com",
        "https://docker.mirrors.ustc.edu.cn",
        "https://kfwkfulq.mirror.aliyuncs.com"
    ]
}
```

3. 重启docker

```shell
sudo service docker restart
```

4. 查看源是否生效

```shell
sudo docker info | grep Mirrors -A 4
```

执行前后端代码的方法：

* 进入`backend/deploy`目录，执行

```shell
sudo docker-compose up
```

注意这里需要提前安装`docker-commpose`

* 进入`frontend/vues`目录，执行

```shell
docker build -t my-nginx-image .
```

构建镜像，然后执行

```shell
docker run -d -p 80:80 --name my-nginx-container my-nginx-image
```

启动容器

* 最后进入`pythonServer`目录执行脚本`runPythonServer.sh`

```shell
bash runPythonServer.sh
```

至此，服务启动完毕

<font color="red">注意：这里可能会遇到如下问题：</font>

![image-20240407232731671](.\error.png)

这是因为您的snmp环境需要额外配置，下面是配置教程，可能会花费5-10分钟：

<https://cloud.tencent.com/developer/article/1833931>

如果您还遇到了其他问题，请首先使用sudo提权尝试解决，如果仍无法解决，请您联系组长（**张瀚文**）

#### 2.5 包过滤防火墙

防火墙实现的代码位于`ModFirewall`目录，由于防火墙涉及内核级操作，所以我们并未将其与其他模块一同集成在前端，而是启动GUI对过滤规则进行配置

单独启动该功能的方法为进入Gui目录，执行

```shell
./run
```

