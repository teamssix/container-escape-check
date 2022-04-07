#!/bin/bash


echo -e ""
echo -e "\033[34m=============================================================\033[0m"
echo -e "\033[34m                Containers Escape Check v0.3                 \033[0m"
echo -e "\033[34m-------------------------------------------------------------\033[0m"
echo -e "\033[34m                     Author:  TeamsSix                       \033[0m"
echo -e "\033[34m                     Twitter: TeamsSix                       \033[0m"
echo -e "\033[34m                     Blog: teamssix.com                      \033[0m"
echo -e "\033[34m             WeChat Official Accounts: TeamsSix              \033[0m"
echo -e "\033[34m Project Address: github.com/teamssix/container-escape-check \033[0m"
echo -e "\033[34m=============================================================\033[0m"
echo -e ""

# Supported detection methods:
# 
# 1. Privileged Mode
# 2. Mount Docker Socket
# 3. Mount Procfs
# 4. Mount Root Directory
# 5. Open Docker Remote API
# 6. CVE-2016-5195 DirtyCow
# 7. CVE-2020-14386 
# 8. CVE-2022-0847 DirtyPipe
# 9. CVE-2017-1000112
# 10. CVE-2021-22555
# 11. Mount Host Var Log
# 12. CAP_DAC_READ_SEARCH
# 13. CAP_SYS_ADMIN
# 14. CAP_SYS_PTRACE
# 15. CVE-2022-0492


CheckCommandExists(){
    $1 >/dev/null 2>&1
    ret=$?
    if [ "$ret" -eq 0 ]; then
        return 1
    fi
    return 0
}


# Install command
InstallCommand(){
    # install command if not present    
    CheckCommandExists $1
    if [ $? -eq 0 ]; then
        # Check network
        timeout 3 bash -c "echo -e >/dev/tcp/baidu.com/80" > /dev/null 2>&1 && IsNetWork=1 || IsNetWork=0
        if [ $IsNetWork -eq 1 ];then
            echo -e "\033[93m[!] It is detected that the $1 command does not exist in the current system, and the command is being installed.\033[0m"

            CheckCommandExists sudo
            if [ $? -eq 0 ]; then
                CheckCommandExists apt-get
                if [ $? -eq 0 ];then
                    if [ "$1" = "capsh" ];then
                        apt-get -y update >/dev/null 2>&1 && apt-get install -y libcap2-bin >/dev/null 2>&1
                    else
                        apt-get -y update >/dev/null 2>&1 && apt-get install -y $1 >/dev/null 2>&1
                    fi
                fi
                CheckCommandExists yum
                if [ $? -eq 0 ];then
                    if [ "$1" = "capsh" ];then
                        yum -y update >/dev/null 2>&1 && yum install -y libcap >/dev/null 2>&1
                    else
                        yum -y update >/dev/null 2>&1 && yum install -y $1 >/dev/null 2>&1
                    fi
                fi
            else
                CheckCommandExists apt-get
                if [ $? -eq 0 ];then
                    if [ "$1" = "capsh" ];then
                        sudo apt-get -y update >/dev/null 2>&1 && apt-get install -y libcap2-bin >/dev/null 2>&1
                    else
                        sudo apt-get -y update >/dev/null 2>&1 && apt-get install -y $1 >/dev/null 2>&1
                    fi
                fi
                CheckCommandExists yum
                if [ $? -eq 0 ];then
                    if [ "$1" = "capsh" ];then
                        sudo yum -y update >/dev/null 2>&1 && yum install -y libcap >/dev/null 2>&1
                    else
                        sudo yum -y update >/dev/null 2>&1 && yum install -y $1 >/dev/null 2>&1
                    fi
                fi
            fi
            CheckCommandExists $1
            if [ $? -eq 0 ]; then
                echo -e "\033[93m[!] $1 command installation failed.\033[0m"
            else
                echo -e "\033[93m[!] $1 command installation completed.\033[0m"
            fi
        fi
    fi
}


# 0. Check The Current Environment
CheckTheCurrentEnvironment(){
    if [ ! -f "/proc/1/cgroup" ];then
        IsContainer=0
    else
        cat /proc/1/cgroup | grep -qi docker && IsContainer=1 || IsContainer=0
    fi

    if [ $IsContainer -eq 0 ];then
        echo -e "\033[31m[-] Not currently a container environment.\033[0m"
        exit 1
    else
        echo -e "\033[33m[!] Currently in a container, checking ......\033[0m"
        VulnerabilityExists=0
    fi
}


# 1. Check Privileged Mode
CheckPrivilegedMode(){
    if [ ! -f "/proc/self/status" ];then
        IsPrivilegedMode=0
    else
        cat /proc/self/status | grep -qi "0000003fffffffff" && IsPrivilegedMode=1 || IsPrivilegedMode=0
        cat /proc/self/status | grep -qi "0000001fffffffff" && IsPrivilegedMode=1 || IsPrivilegedMode=0
    fi

    if [ $IsPrivilegedMode -eq 1 ];then
        echo -e "\033[92m[+] The current container is in privileged mode.\033[0m"
        VulnerabilityExists=1
    fi
    
}


# 2. Check Docker Socket Mount
CheckDockerSocketMount(){
    if [ ! -f "/var/run/docker.sock" ];then
        IsDockerSocketMount=0
    else
        ls /var/run/ | grep -qi docker.sock && IsDockerSocketMount=1 || IsDockerSocketMount=0
    fi
    
    if [ $IsDockerSocketMount -eq 1 ];then
        echo -e "\033[92m[+] The current container has docker socket mounted.\033[0m"
        VulnerabilityExists=1
    fi
}


# 3. Check Procfs Mount
CheckProcfsMount(){

    find / -name core_pattern 2>/dev/null | wc -l | grep -q 2 && IsProcfsMount=1 || IsProcfsMount=0

    if [ $IsProcfsMount -eq 1 ];then
        echo -e "\033[92m[+] The current container has procfs mounted.\033[0m"
        VulnerabilityExists=1
    fi
}


# 4. Check Root Directory Mount
CheckRootDirectoryMount(){

    find / -name passwd 2>/dev/null | grep /etc/passwd | wc -l | grep -q 7 && IsRootDirectoryMount=1 || IsRootDirectoryMount=0

    if [ $IsRootDirectoryMount -eq 1 ];then
        echo -e "\033[92m[+] The current container has root directory mounted.\033[0m"
        VulnerabilityExists=1
    fi
}


# 5. Check Docker Remote API
CheckDockerRemoteAPI(){
    InstallCommand hostname
    for PORT in "2375" "2376"
    do 
        IP=`hostname -i | awk -F. '{print $1 "." $2 "." $3 ".1"}' ` && timeout 3 bash -c "echo -e >/dev/tcp/$IP/$PORT" > /dev/null 2>&1 && DockerRemoteAPIIsEnabled=1 || DockerRemoteAPIIsEnabled=0
        if [ $DockerRemoteAPIIsEnabled -eq 1 ];then
            echo -e "\033[92m[+] The Docker Remote API for the current container is enabled.\033[0m"
            VulnerabilityExists=1
        fi
    done
}


LinuxKernelVersion=`uname -r | awk -F '-' '{print $1}'`
KernelVersion=`echo -e $LinuxKernelVersion | awk -F '.' '{print $1}'`
MajorRevision=`echo -e $LinuxKernelVersion | awk -F '.' '{print $2}'`
MinorRevision=`echo -e $LinuxKernelVersion | awk -F '.' '{print $3}'`


# 6. Check CVE-2016-5195 DirtyCow
# 2.6.22 <= ver <= 4.8.3
CheckCVE_2016_5195DirtyCow(){
    # 2.6.22 <= ver <= 2.6.xx
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -eq 6 && "$MinorRevision" -ge 22 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2016-5195 DirtyCow vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # 2.7 <= ver <= 2.x
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -ge 7 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2016-5195 DirtyCow vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # ver = 3
    if [[ "$KernelVersion" -eq 3 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2016-5195 DirtyCow vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # 4.x <= ver <= 4.8
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -lt 8 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2016-5195 DirtyCow vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # 4.8.x <= ver <= 4.8.3
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -eq 8 && "$MinorRevision" -le 3 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2016-5195 DirtyCow vulnerability.\033[0m"
        VulnerabilityExists=1
    fi
}


# 7. CVE-2020-14386
# 4.6 <= ver < 5.9 
CheckCVE_2020_14386(){
    # 4.6 <= ver < 4.x
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -ge 6 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2020-14386 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # 5.x <= ver < 5.9
    if [[ $KernelVersion -eq 5 && $MajorRevision -lt 9 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2020-14386 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi
}


# 8. CVE-2022-0847 DirtyPipe
# 5.8 <= ver < 5.10.102 < ver < 5.15.25 <  ver <  5.16.11
CheckCVE_2022_0847(){
    if [ $KernelVersion -eq 5 ];then
        # 5.8 <= ver < 5.10.x
        if [[ "$MajorRevision" -ge 8 && "$MajorRevision" -lt 10 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi
        # 5.10.x <= ver < 5.10.102
        if [[ "$MajorRevision" -eq 10 && "$MinorRevision" -lt 102 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi
        # 5.10.102 < ver <= 5.10.x
        if [[ "$MajorRevision" -eq 10 && "$MinorRevision" -gt 102 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi

        # 5.10.x < ver < 5.15.x
        if [[ "$MajorRevision" -gt 10 && "$MajorRevision" -lt 15 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi

        # 5.15.x <= ver < 5.15.25
        if [[ "$MajorRevision" -eq 15 && "$MinorRevision" -lt 25 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi
        # 5.15.25 < ver <= 5.15.x
        if [[ "$MajorRevision" -eq 15 && "$MinorRevision" -gt 25 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi

        # 5.16.x <= ver < 5.16.11
        if [[ "$MajorRevision" -eq 16 && "$MinorRevision" -lt 11 ]];then
            echo -e "\033[92m[+] The current container has the CVE-2022-0847 DirtyPipe vulnerability.\033[0m"
            VulnerabilityExists=1
        fi
    fi
}


# 9. CVE-2017-1000112
# 4.4 <= ver<=4.13
CheckCVE_2017_1000112(){
    # 4.4 <= ver <= 4.13
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -ge 4 && "$MajorRevision" -le 13 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2017-1000112 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi
}


# 10. CVE-2021-22555
# 2.6.19 <= ver <= 5.12
CheckCVE_2021_22555(){
    # 2.6.19 <= ver <= 2.6.xx
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -eq 6 && "$MinorRevision" -ge 19 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2021-22555 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi
    # 2.7 <= ver <= 2.x
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -ge 7 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2021-22555 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # ver = 3 or ver = 4
    if [[ "$KernelVersion" -eq 3 || "$KernelVersion" -eq 4 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2021-22555 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi

    # 5.x <= ver <= 5.12
    if [[ $KernelVersion -eq 5 && $MajorRevision -le 12 ]];then
        echo -e "\033[92m[+] The current container has the CVE-2021-22555 vulnerability.\033[0m"
        VulnerabilityExists=1
    fi
}


# 11. Mount Host Var Log
CheckVarLogMount(){
    if [ ! -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ];then
        IsPodEnv=0
    else
        IsPodEnv=1
    fi
    if [ $IsPodEnv -eq 1 ];then
        find / -name lastlog 2>/dev/null | wc -l | grep -q 3 && IsVarLogMount=1 || IsVarLogMount=0
        if [ $IsVarLogMount -eq 1 ];then
            echo -e "\033[92m[+] The current container has /var/log mounted.\033[0m"
            VulnerabilityExists=1
        fi
    fi
}


# 12. Check CAP_DAC_READ_SEARCH
ChekckCAP_DAC_READ_SEARCH(){
    if command -v capsh >/dev/null 2>&1; then
        cap_dac_read_searchNum=`capsh --print | grep cap_dac_read_search | wc -l`
        if [ $cap_dac_read_searchNum -gt 0 ];then
            echo -e "\033[92m[+] The current container has the CAP_DAC_READ_SEARCH permission.\033[0m"
            VulnerabilityExists=1
        fi
    fi    
}


# 13. Check CAP_SYS_ADMIN
CheckCAP_SYS_ADMIN(){
    if command -v capsh >/dev/null 2>&1; then
        cap_sys_adminNum=`capsh --print | grep cap_sys_admin | wc -l`
        if [ $cap_sys_adminNum -gt 0 ];then
            echo -e "\033[92m[+] The current container has the CAP_SYS_ADMIN permission.\033[0m"
            VulnerabilityExists=1
        fi
    fi    
}


# 14. Check CAP_SYS_PTRACE
CheckCAP_SYS_PTRACE(){
    if command -v capsh >/dev/null 2>&1; then
        cap_sys_ptraceNum=`capsh --print | grep cap_sys_ptrace | wc -l`
        if [ $cap_sys_ptraceNum -gt 0 ];then
            echo -e "\033[92m[+] The current container has the CAP_SYS_PTRACE permission.\033[0m"
            VulnerabilityExists=1
        fi
    fi    
}


# 15. Check CVE-2022-0492, Code By https://github.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492/blob/main/can-ctr-escape-cve-2022-0492.sh
CheckCVE_2022_0492(){
    # Setup test dir
    test_dir=/tmp/.cve-2022-0492-test
    if mkdir -p $test_dir ; then
        # Test whether escape via user namespaces is possible
        while read -r subsys
        do
            if unshare -UrmC --propagation=unchanged bash -c "mount -t cgroup -o $subsys cgroup $test_dir 2>&1 >/dev/null && test -w $test_dir/release_agent" >/dev/null 2>&1 ; then
                echo -e "\033[92m[+] The current container has the CVE-2022-0492 vulnerability.\033[0m"
            fi
        done <<< $(cat /proc/$$/cgroup | grep -Eo '[0-9]+:[^:]+' | grep -Eo '[^:]+$')
        umount $test_dir >/dev/null 2>&1 && rm -rf $test_dir >/dev/null 2>&1
    fi    
}


main()  
{  
   # 0. Check the current environment
    CheckTheCurrentEnvironment

    # 1. Check Privileged Mode
    CheckPrivilegedMode

    # 2. Check Docker Socket Mount
    CheckDockerSocketMount

    # 3. Check Procfs Mount
    CheckProcfsMount

    # 4. Check Root Directory Mount
    CheckRootDirectoryMount

    # 5. Check Docker Remote API
    CheckDockerRemoteAPI

    # 6. Check CVE-2016-5195 DirtyCow
    CheckCVE_2016_5195DirtyCow

    # 7. CVE-2020-14386
    CheckCVE_2020_14386

    # 8. CVE-2022-0847 DirtyPipe
    CheckCVE_2022_0847

    # 9. CVE-2017-1000112
    CheckCVE_2017_1000112

    # 10. CVE-2021-22555
    CheckCVE_2021_22555

    # 11. Mount Host Var Log
    CheckVarLogMount

    InstallCommand capsh

    # 12. Check CAP_DAC_READ_SEARCH
    ChekckCAP_DAC_READ_SEARCH

    # 13. Check CAP_SYS_ADMIN
    CheckCAP_SYS_ADMIN 

    # 14. Check CAP_SYS_PTRACE
    CheckCAP_SYS_PTRACE

    # 15. Check CVE-2022-0492
    CheckCVE_2022_0492


    if [ $VulnerabilityExists -eq 0 ];then
        echo -e "\033[33m[!] Check completed, no vulnerability found. \033[0m"
    else
        echo -e "\033[33m[!] Check completed.\033[0m"
    fi
}

main