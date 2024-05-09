#!/bin/bash

########################################################################################################################
#                             Linux Incident Response Script Renewal-Zero-Collector                             #
#                                      Cyberone SOC mss_analysis@cyberone.kr                                      #
########################################################################################################################

output_dir="tmp/C1_LISA"

mkdir -p "$output_dir/Info"
mkdir -p "$output_dir/File"

mkdir -p "$output_dir/Users"
user_dir="$output_dir/Users"
mkdir -p "$user_dir/History"
mkdir -p "$user_dir/Login"
mkdir -p "$user_dir/Logout"

mkdir -p "$output_dir/Logs"
mkdir -p "$output_dir/Cron"
mkdir -p "$output_dir/IP Tables && Network"
mkdir -p "$output_dir/Process"
mkdir -p "$output_dir/Disk"
mkdir -p "$output_dir/SSH"
mkdir -p "$output_dir/PAM"


logfile="$output_dir/forensics_log.txt"

write_output() {
	command=$1
	filename=$2
	art_dir=$3
	if $command >> "$output_dir/$art_dir/$filename" 2>&1; then
		echo "[+] Successfully executed: $command" >> "$logfile"
	else
		echo "[-] Failed to executed: $command" >> "$logfile"
	fi
}

echo "Forensic data extraction started at $(date)" > "$logfile"
echo "" >> "$logfile"

### Info
## Hostname
write_output "hostname" "Hostname" "Info"

## SystemID
write_output "uname -a" "System_ID" "Info"

## 마지막 로그인 시간 수집 
write_output "last -a -i" "Wtmp" "Info"

## who 명령어 결과 수집 
write_output "who" "who" "Info"

write_output "uptime" "uptime" "Info"

### File
## file_time_stamp
write_output "find / -path /proc -xdev -prune -o -printf '%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%g;%s;%p\n'" "file_time_stamp" "File"

# 현재 열려 있는 파일들에 대한 정보 출력 ( n 옵션 )
lsof -n

# ELF 파일이 어떤 RPM 패키지에 속하는 지 출력
write_output "lsof -F n | awk '/^n/ && /ELF/ {print $2}' | sort -u | while read file; do rpm -qf "$file"; done" "rpm_package" "File"

# 파일 속성 확인
write_output "stat /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin" "binary_file" "File"

# 디버깅 정보가 제거되지 않은 파일 필터링 후 수집
write_output "file /bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/local/bin/* /usr/local/sbin/* | grep 'not strip'" "Check_binary" "File"

# 각 디렉토리에 있는 파일 중 "execu"라는 문자열을 포함하는 파일 수집
write_output "file /lib/* /usr/lib/* /lib64/* /usr/lib64/* /usr/local/lib/* /usr/local/lib64/* | grep 'execu'" "Check_Execute" "File"

# dev 폴더의 하위에서 일반적인 파일만 검색
write_output "find /dev -type f -exec file {} \;" "fine_dev" "File"



### Users
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
		write_output "cat $user_home/.bash_history" "bash_history_$username" "Users"
	else
		echo "no .bash_history for $username" >> "$output_dir/Users/bash_history_$username"
		write_output "cat $user_home/.bash_history" "bash_history_$username" "Users"
	fi

	if [ -f "$user_home/.zsh_history" ]; then
		write_output "cat $user_home/.zsh_history" "zsh_history_$username" "Users"
	else
		echo "no .zsh_history for $username" >> "$output_dir/Users/zsh_history_$username"
		write_output "cat $user_home/.zsh_history" "zsh_history_$username" "Users"
	fi

	write_output "cat $user_home/.local/share/recently-used.xbel" "recently_used_files_$username" "Users"
done

## Login
write_output "cat /etc/bash.bashrc" "etc_bashrc" "Login"

for user_login in /home/* ; do
	username=$(basename "$user_login")

	if [ -f "$user_login/.bashrc" ]; then
		write_output "cat $user_login/.bashrc" "bashrc_$username" "Login"
	else
		echo "no .bashrc for $username" >> "$output_dir/Login/bashrc_$username"
		write_output "cat $user_login/.bashrc" "bashrc_$username" "Login"
	fi

	if [ -f "$user_login/.bash_profile" ]; then
		write_output "cat $user_login/.bash_profile" "bash_profile_$username" "Login"
	else
		echo "no .bash_profile for $username" >> "$output_dir/Login/bash_profile_$username"
		write_output "cat $user_login/.bash_profile" "bash_profile_$username" "Login"
	fi
done

## Logout
write_output "cat /etc/.bash_logout" "etc_logout" "Logout"

for user_logout in /home/* ; do
	username=$(basename "$user_logout")

	if [ -f "$user_logout/.bash_logout" ]; then
		write_output "cat $user_logout/.bash_logout" "logout_$username" "Logout"
	else
		echo "no .bash_logout for $username" >> "$output_dir/Logout/logout_$username"
		write_output "cat $user_logout/.bash_logout" "logout_$username" "Logout"
	fi
done


### IP Tables && Network
## hosts 관련 파일 수집 
write_output "cat /etc/hosts" "hosts." "IP Tables && Network"
write_output "cat /etc/hosts.allow" "hosts_allow" "IP Tables && Network"
write_output "cat /etc/hosts.deny" "host_deny" "IP Tables && Network"

## 현재 열려 있는 네트워크 연결에 대한 정보 출력 ( i 옵션 )
lsof -i 

### Process
## 현재 시스템에 로드된 커널 모듈의 목록을 표시
write_output "lsmod" "lsmod" "Process"

write_output "df -k" "df" "Process"


### Disk
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


### Logs
## 주요 로그 수집
logs=("secure*" "messages*" "yum*" "dmesg*" "cron*" "auth*" "syslog*" "xferlog*")

for log_pattern in "${logs[@]}"; do
	for log in /var/log/$log_pattern; do
		logname=4(basename "$log")
		if [ -f "$log" ]; then
			write_output "cat $log" "$logname" "Logs"
		else
			echo "No Logfile for $logname" >> "$output_dir/Logs/$logname"
			write_output "cat $log" "$logname" "Logs"
		fi
	done
done

### Cron
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


### SSH


### PAM




result_file="/tmp/C1_LISA/forensics_log"

count_success=$(grep -C '^\[+\]' "$result_file")
count_fail=$(grep -C '^\[-\]' "$result_file")

echo "" >> "$logfile"
echo "---------- Number of successful operations: $count_success ----------" >> "$result_file"
echo "----------   Number of failed operations: $count_fail   ----------" >> "$result_file"

grep '^\[-\]' "$result_file" > "/tmp/C1_LISA/failed"

echo "" >> "$logfile"
echo "Forensic data extraction ended at $(date)" >> "$logfile"

echo -e "\e[1;34m\nCompleted!\e[0m"