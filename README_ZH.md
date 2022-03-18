中文 | [EN](https://github.com/teamssix/container-escape-check/blob/master/README.md)

# 介绍

这个脚本用来检测 Docker 容器中的逃逸方法，目前支持以下几种方法：

1. 处于特权模式
2. 挂载了 Docker Socket
3. 挂载了 Procfs
4. 挂载了宿主机根目录
5. 开启了 Docker 远程 API 访问接口
6. CVE-2016-5195 DirtyCow 脏牛漏洞
7. CVE-2020-14386 
8. CVE-2022-0847 DirtyPipe

# 使用

在 Docker 容器中一键运行：

```
wget https://raw.githubusercontent.com/teamssix/container-escape-check/main/container-escape-check.sh -O - | bash
```

或者克隆项目到容器中运行：

```
git clone https://github.com/teamssix/container-escape-check.git
cd container-escape-check
chmod +x container-escape-check.sh
./container-escape-check.sh
```

![](./img.png)

# 注意：

* 这个脚本需要在 Docker 容器中运行
* 这里的检测方法大多是基于我自己的经验，可能会存在检测误检或者漏检的情况，如果您发现了这种情况，欢迎提 Issue
* 由于有的逃逸方法需要根据目标 Docker 的版本去判断，这里我暂时还没想到从容器内部获取 Docker 版本的方法，因此脚本暂时还不支持这块儿的检测。

![img](https://cdn.jsdelivr.net/gh/teamssix/BlogImages/imgs/TeamsSix_Subscription_Logo2.png)
