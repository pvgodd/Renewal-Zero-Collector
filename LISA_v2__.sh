#!/bin/bash
# V2.2
##############################################################################################################
#                                        Linux Incident Response Script Renewal-Zero-Collector               #
#                                        Cyberone SOC mss_analysis@cyberone.kr                               #
##############################################################################################################



output_dir="/tmp/C1_LISA"

mkdir -p "$output_dir/Info"


mkdir -p "$output_dir/File"
file_dir="$output_dir/File"
mkdir -p "$file_dir/Webshell"

mkdir -p "$output_dir/Users"
users_dir="$output_dir/Users"
mkdir -p "$users_dir/History"
mkdir -p "$users_dir/Login"
mkdir -p "$users_dir/Logout"

mkdir -p "$output_dir/Logs"
mkdir -p "$output_dir/Cron"
mkdir -p "$output_dir/IP Tables && Network"
mkdir -p "$output_dir/Process"
mkdir -p "$output_dir/Disk"
mkdir -p "$output_dir/SSH"
mkdir -p "$output_dir/PAM"

logfile="$output_dir/forensics_log.txt"


#### Main_Directory ####
write_output() {
    command=$1
    filename=$2
    art_dir=$3
    if $command >> "$output_dir/$art_dir/$filename" 2>&1; then
        echo "[+] Successfully executed: $command" >> "$logfile"
    else
        echo "[-] Failed to execute: $command" >> "$logfile"
    fi
}

#### File_Sub_Directory ####
file_write_output() {
    command=$1
    filename=$2
    art_dir=$3
    if $command >> "$file_dir/$art_dir/$filename" 2>&1; then
        echo "[+] Successfully executed: $command" >> "$logfile"
    else
        echo "[-] Failed to execute: $command" >> "$logfile"
    fi
}

#### Users_Sub_Directory ####
users_write_output() {
    command=$1
    filename=$2
    art_dir=$3
    if $command >> "$users_dir/$art_dir/$filename" 2>&1; then
        echo "[+] Successfully executed: $command" >> "$logfile"
    else
        echo "[-] Failed to execute: $command" >> "$logfile"
    fi
}


echo "Forensic data extraction started at $(date)" > "$logfile"
echo "" >> "$logfile"

#### ----- Info ----- ####
## Hostname
write_output "hostname" "Hostname" "Info"

## SystemID
write_output "uname -a" "System_ID" "Info"

## 마지막 로그인 시간 수집 
write_output "last -a -i" "Wtmp" "Info"

## who 명령어 결과 수집 
write_output "who" "who" "Info"

write_output "uptime" "uptime" "Info"

####------------------####

#### ----- Files ----- ####
## file_time_stamp
write_output "find / -path /proc -xdev -prune -o -printf '%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%g;%s;%p\n'" "file_time_stamp" "File"

# 현재 열려 있는 파일들에 대한 정보 출력 ( n 옵션 ) ************************w*

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
# ELF 파일이 어떤 RPM 패키지에 속하는 지 출력 ($file path err => add path)
# write_output "lsof -F n | awk '/^n/ && /ELF/ {print $2}' | sort -u | while read file; do rpm -qf "$file"; done" "rpm_package" "File"

# 파일 속성 확인
write_output "stat /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin" "binary_file" "File"

# 디버깅 정보가 제거되지 않은 파일 필터링 후 수집
write_output "file /bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/local/bin/* /usr/local/sbin/* | grep 'not strip'" "Check_binary" "File"


##webshell
# Monitor Apache configuration files
file_write_output "tail -f /etc/apache2/*/*" "Check_apache2" "Websehll"

# Monitor Nginx configuration files
file_write_output "tail -f /etc/nginx/*/*" "Check_nginx" "Webshell"

# 각 디렉토리에 있는 파일 중 "execu"라는 문자열을 포함하는 파일 수집
write_output "file /lib/* /usr/lib/* /lib64/* /usr/lib64/* /usr/local/lib/* /usr/local/lib64/* | grep 'execu'" "Check_Execute" "File"

# dev 폴더의 하위에서 일반적인 파일만 검색
write_output "find /dev -type f -exec file {} \;" "fine_dev" "File"

# if then:
# file_write_output "find /var/www/html -type f -name '*.php' -printf '%T@ %f' | sort -n | awk '{print strftime('%Y-%m-%d %H:%M:%S', $1), $2}'
# # " "Ceck_Webshell" "Webshell"
####------------------####


#### ----- Users ----- ####
## passwd 파일 수집
write_output "cat /etc/passwd" "passwd" "Users"

## shadow 파일 수집 
write_output "cat /etc/shadow" "shadow" "Users"

## group 파일 수집
write_output "cat /etc/group" "group" "Users"

## 사용자 별 History 수집
for user_home in /home/* /root; do
    username=$(basename "$user_home")

    if [ -f "$user_home/.bash_history" ]; then
        users_write_output "cat $user_home/.bash_history" "bash_history_$username" "History"
    else
        echo "no .bash_history for $username" >> "$users_dir/History/bash_history_$username"
        users_write_output "cat $user_home/.bash_history" "bash_history_$username" "History"
    fi

    if [ -f "$user_home/.zsh_history" ]; then
        users_write_output "cat $user_home/.zsh_history" "zsh_history_$username" "History"
    else
        echo "no .zsh_history for $username" >> "$users_dir/History/zsh_history_$username"
        users_write_output "cat $user_home/.zsh_history" "zsh_history_$username" "History"
    fi

    users_write_output "cat $user_home/.local/share/recently-used.xbel" "recently_used_files_$username" "History"
done

## 사용자 별 ftp History 수집 Test
for user_home in /home/* /root; do
    username=$(basename "$user_home")

    if [ -f "$user_home/.ftp_history" ]; then
        users_write_output "cat $user_home/.ftp_history" "ftp_history_$username" "History"
    else
        echo "no .ftp_history for $username" >> "$users_dir/History/bash_history_$username"
        users_write_output "cat $user_home/.ftp_history" "ftp_history_$username" "History"
    fi

    if [ -f "$user_home/.sftp_history" ]; then
        users_write_output "cat $user_home/.sftp_history" "sftp_history_$username" "History"
    else
        echo "no .sftp_history for $username" >> "$users_dir/History/zsh_history_$username"
        users_write_output "cat $user_home/.sftp_history" "sftp_history_$username" "History"
    fi

done

## 사용자 별 etc History 수집 Test
for user_home in /home/* /root; do
    username=$(basename "$user_home")

    if [ -f "$user_home/.viminfo" ]; then
        users_write_output "cat $user_home/.viminfo" "viminfo_$username" "History"
    else
        echo "no .viminfo for $username" >> "$users_dir/History/bash_history_$username"
        users_write_output "cat $user_home/.viminfo" "viminfo_$username" "History"
    fi

    if [ -f "$user_home/.lesshst" ]; then
        users_write_output "cat $user_home/.lesshst" "lesshst_$username" "History"
    else
        echo "no .lesshst for $username" >> "$users_dir/History/zsh_history_$username"
        users_write_output "cat $user_home/.lesshst" "lesshst_$username" "History"
    fi

    if [ -f "$user_home/.mysql_history" ]; then
        users_write_output "cat $user_home/.mysql_history" "mysql_history_$username" "History"
    else
        echo "no .mysql_history for $username" >> "$users_dir/History/mysql_history_$username"
        users_write_output "cat $user_home/.mysql_history" "mysql_history_$username" "History"
    fi

done

## 사용자 별 exl History 수집 Test
for user_home in /home/* /root; do
    username=$(basename "$user_home")

    if [ -f "$user_home/.mozilla" ]; then
        users_write_output "cat $user_home/.mozilla" "mozilla_$username" "History"
    else
        echo "no .mozilla for $username" >> "$users_dir/History/mozilla_$username"
        users_write_output "cat $user_home/.mozilla" "mozilla_$username" "History"
    fi

    if [ -f "$user_home/.config/google-chrome" ]; then
        users_write_output "cat $user_home/.config/google-chrome" "chrome_$username" "History"
    else
        echo "no .config/google-chrome for $username" >> "$users_dir/History/chrome_$username"
        users_write_output "cat $user_home/.config/google-chrome" "chrome_$username" "History"
    fi

done

## 사용자 별 git History 수집 Test
for user_home in /home/* /root; do
    username=$(basename "$user_home")

    if [ -f "$user_home/.gitconfig" ]; then
        users_write_output "cat $user_home/.gitconfig" "gitconfig_$username" "History"
    else
        echo "no .gitconfig for $username" >> "$users_dir/History/gitconfig_$username"
        users_write_output "cat $user_home/.gitconfig" "gitconfig_$username" "History"
    fi

    if [ -f "$user_home/.git/logs" ]; then
        users_write_output "cat $user_home/.git/logs" "git_history_$username" "History"
    else
        echo "no .git_logs for $username" >> "$users_dir/History/git_history_$username"
        users_write_output "cat $user_home/.git/logs" "git_history_$username" "History"
    fi

done

## Login
users_write_output "cat /etc/bash.bashrc" "etc_bashrc" "Login"

for user_login in /home/* ; do
    username=$(basename "$user_login")

    if [ -f "$user_login/.bashrc" ]; then
        users_write_output "cat $user_login/.bashrc" "bashrc_$username" "Login"
    else
        echo "no .bashrc for $username" >> "$users_dir/Login/bashrc_$username"
        users_write_output "cat $user_login/.bashrc" "bashrc_$username" "Login"
    fi

    if [ -f "$user_login/.bash_profile" ]; then
        users_write_output "cat $user_login/.bash_profile" "bash_profile_$username" "Login"
    else
        echo "no .bash_profile for $username" >> "$users_dir/Login/bash_profile_$username"
        users_write_output "cat $usera_login/.bash_profile" "bash_profile_$username" "Login"
    fi
done

## Logout
users_write_output "cat /etc/.bash_logout" "etc_logout" "Logout"

for user_logout in /home/* ; do
    username=$(basename "$user_logout")

    if [ -f "$user_logout/.bash_logout" ]; then
        users_write_output "cat $user_logout/.bash_logout" "logout_$username" "Logout"
    else
        echo "no .bash_logout for $username" >> "$users_dir/Logout/logout_$username"
        users_write_output "cat $user_logout/.bash_logout" "logout_$username" "Logout"
    fi
done
####------------------####


#### ----- IP Tables && Network ----- ####
## hosts 관련 파일 수집 
write_output "cat /etc/hosts" "hosts." "IP Tables && Network"
write_output "cat /etc/hosts.allow" "hosts_allow" "IP Tables && Network"
write_output "cat /etc/hosts.deny" "host_deny" "IP Tables && Network"

## 현재 열려 있는 네트워크 연결에 대한 정보 출력 ( i 옵션 )
write_output "lsof -i" "losf_i" "IP Tables && Network"
####------------------####

#### ----- Process ----- ####
## 현재 시스템에 로드된 커널 모듈의 목록을 표시
write_output "lsmod" "lsmod" "Process"

write_output "df -k" "df" "Process"
####------------------####


#### ----- Disk ----- ####
## 시스템에 연결된 모든 디스크의 파티션 정보
write_output "fdisk -l" "fdisk" "Disk"

## Mount
write_output "mount" "mount" "Disk"

usb_mount_path=$(df -P | awk '$6 ~ /^\/media\/.*[0-9A-Fa-f]/{print $6}')
if [ -n "$usb_mount_path" ]; then
    cp -r "$usb_mount_path" "$output_dir/Disk"
    echo "[+] Check the USB mount" >> "$output_dir/Disk/USB_mount"
else
    echo "[-] USB mount not found" >> "$output_dir/Disk/USB_mount"
fi
####------------------####

### Logs
## 주요 로그 수집
logs=("secure*" "messages*" "yum*" "dmesg*" "cron*" "auth*" "syslog*" "xferlog*")

for log_pattern in "${logs[@]}"; do
    for log in /var/log/$log_pattern; do
        logname=$(basename "$log")
        if [ -f "$log" ]; then
            write_output "cat $log" "$logname" "Logs"
        else
            echo "No Logfile for $logname" >> "$output_dir/Logs/$logname"
            write_output "cat $log" "$logname" "Logs"
        fi
    done
done



### ----- SSH ----- ###

# View the SSH service configuration managed by systemd
write_output "cat /lib/systemd/system/ssh.service" "ssh_service" "SSH"

# View the SSH daemon configuration file
write_output "cat /etc/ssh/ssh_config" "sshd_config" "SSH"

# List any user-specific SSH resource files in the ~/.ssh directory
write_output "ls ~/.ssh/rc" "rc" "SSH"

# List system-wide SSH resource files in the /etc/ssh directory
write_output "ls /etc/ssh/sshrc" "sshrc" "SSH"
####------------------####


### ----- PAM ----- ###
# Display contents of the PAM configuration file
write_output "cat /etc/pam.conf" "pam_conf" "PAM"

# Check contents of the PAM directory
write_output "cat /etc/pam.d" "pam_d" "PAM"
####------------------####


### ----- Cron ----- ####
## cron 수집
for log in /var/spool/cron/crontabs/*; do
    logname=$(basename "$log")
    if [ -f "$log" ]; then
        write_output "cat $log" "$logname" "Cron"
    else
        echo "No Logfile for $logname" >> "$output_dir/Cron/$logname"
        write_output "cat $log" "$logname" "Cron"
    fi
done

## 시스템 전체적으로 적용되는 cron 작업 수집
# 검색할 폴더 경로
folder="/etc/"

# 결과를 저장할 파일 경로
cron_file="cron_file"

# 폴더 내의 모든 cron으로 시작하는 디렉토리 리스트 가져오기
directories=$(find "$folder" -type d -name "cron.*")

# 각 디렉토리의 하위 파일 목록과 내용을 가져와서 파일로 저장
for dir in $directories
do
    echo "=============================" >> "$cron_file"
    echo "디렉토리: $dir" >> "$output_dir/Cron/$cron_file"
    echo "=============================" >> "$cron_file"
    find "$dir" -type f -exec sh -c 'echo "파일: {}"; echo "-----------------------------"; cat "{}"; echo "";' \; >> "$output_dir/Cron/$cron_file"
    echo "" >> "$cron_file" "Cron"
done
# ####------------------####



result_file="/tmp/C1_LISA/forensics_log.txt"

count_success=$(grep -c '^\[+\]' "$result_file")
count_fail=$(grep -c '^\[-\]' "$result_file")

echo "" >> "$logfile"
echo "---------- Number of successful operations: $count_success ----------" >> "$result_file"
echo "----------   Number of failed operations: $count_fail   ----------" >> "$result_file"

grep '^\[-\]' "$result_file" > "/tmp/C1_LISA/failed.txt"

echo "" >> "$logfile"
echo "Forensic data extraction ended at $(date)" >> "$logfile"


echo -e "\e[1;34m\nCompleted!\e[0m"
