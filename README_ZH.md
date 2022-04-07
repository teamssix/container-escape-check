# Container Escape Check 容器逃逸检测

[![GitHub stars](https://img.shields.io/github/stars/teamssix/container-escape-check)](https://github.com/teamssix/container-escape-check) [![GitHub issues](https://img.shields.io/github/issues/teamssix/container-escape-check)](https://github.com/teamssix/container-escape-check/issues) [![GitHub release](https://img.shields.io/github/release/teamssix/container-escape-check)](https://github.com/teamssix/container-escape-check/releases)  [![img](https://img.shields.io/badge/author-TeamsSix-blueviolet)](https://github.com/teamssix) [![Twitter](https://img.shields.io/twitter/url/https/twitter.com/teamssix.svg?style=social&label=Follow%20the%20author)](https://twitter.com/teamssix)

![container-escape-check](https://socialify.git.ci/teamssix/container-escape-check/image?description=1&font=Inter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F49087564&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

中文 | [EN](https://github.com/teamssix/container-escape-check/blob/master/README.md)

# 介绍

这个脚本用来检测 Docker 容器中的逃逸方法，目前支持以下几种方法：

1. 容器处于特权模式
2. 挂载了 Docker Socket
3. 挂载了宿主机 Procfs
4. 挂载了宿主机根或者宿主机 etc 目录
5. 开启了 Docker 远程 API 访问接口
6. CVE-2016-5195 DirtyCow 脏牛漏洞
7. CVE-2020-14386 
8. CVE-2022-0847 DirtyPipe
9. CVE-2017-1000112
10. CVE-2021-22555
11. pod 挂载了宿主机 /var/log 目录
12. 当前容器有 CAP_DAC_READ_SEARCH 权限（需要容器支持 capsh 命令）
13. 当前容器有 CAP_SYS_ADMIN 权限（需要容器支持 capsh 命令）
14. 当前容器有 CAP_SYS_PTRACE 权限（需要容器支持 capsh 命令）
14.  CVE-2022-0492

# ✨ 使用

在 Docker 容器中一键运行：

```
wget https://raw.githubusercontent.com/teamssix/container-escape-check/main/container-escape-check.sh -O- | bash
```

或者克隆项目到容器中运行：

```
git clone https://github.com/teamssix/container-escape-check.git
cd container-escape-check
chmod +x container-escape-check.sh
./container-escape-check.sh
```

![](./img.png)

如果感觉还不错，记得给项目点个小星星(star) ✨

# ⚠️ 注意：

* 这个脚本需要在 Docker 容器中运行
* 这里的检测方法大多是基于我自己的经验，可能会存在检测误检或者漏检的情况，如果您发现了这种情况，欢迎提 Issue
* 由于有的逃逸方法需要根据目标 Docker 的版本去判断，这里我暂时还没想到从容器内部获取 Docker 版本的方法，因此脚本暂时还不支持这块儿的检测。

# 更新日志

## v0.3 2022.4.7

- 添加了 CVE-2022-0492
- 如果不存在 capsh 命令则会自动安装
- 增强了特权模式检测
- 增强了 /var/log 检测

## v0.2 2022.3.30

* 添加了 CVE-2017-1000112
* 添加了 CVE-2021-22555
* 添加了 Mount Host Var Log
* 添加了 CAP_DAC_READ_SEARCH
* 添加了 CAP_SYS_ADMIN
* 添加了 CAP_SYS_PTRACE

## v0.1 2022.3.18

* 添加了 Privileged Mode
* 添加了 Mount docker Socket
* 添加了 Mount host procfs
* 添加了 Mount host root or etc directory
* 添加了 Open Docker Remote API
* 添加了 CVE-2016-5195 DirtyCow
* 添加了 CVE-2020-14386 
* 添加了 CVE-2022-0847 DirtyPipe

![img](https://cdn.jsdelivr.net/gh/teamssix/BlogImages/imgs/TeamsSix_Subscription_Logo2.png)
