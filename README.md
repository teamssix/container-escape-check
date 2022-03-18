[中文](https://github.com/teamssix/container-escape-check/blob/master/README_ZH.md) | EN

# Introduce

This script is used to detect Docker container escape methods, The following methods are currently supported:

1. Privileged Mode
2. Mount Docker Socket
3. Mount Procfs
4. Mount Root Directory
5. Open Docker Remote API
6. CVE-2016-5195 DirtyCow
7. CVE-2020-14386 
8. CVE-2022-0847 DirtyPipe

# Usage

Run this script with one command in the container.

```
wget https://raw.githubusercontent.com/teamssix/container-escape-check/main/container-escape-check.sh | bash
```

Or clone the project to run in the container.

```
git clone https://github.com/teamssix/container-escape-check.git
cd container-escape-check
chmod +x container-escape-check.sh
./container-escape-check.sh
```

![](https://cdn.jsdelivr.net/gh/teamssix/BlogImages/imgs/202203181518954.png)

# Notes

* This script needs to be run inside the docker container.

* Most of the detection methods here are based on my experience, and there may be false positives or omissions. If you find these problems, please submit an Issue.
* Some escape methods need to be judged according to the Docker version. I haven't thought of a way to get the Docker version from inside the container, so the script does not support the detection of this method yet.

![img](https://cdn.jsdelivr.net/gh/teamssix/BlogImages/imgs/TeamsSix_Subscription_Logo2.png)
