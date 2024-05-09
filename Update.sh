#!/bin/bash

########################################################################################################################
#                             Linux Incident Response Script Renewal-Zero-Collector                             #
#                                      Cyberone SOC mss_analysis@cyberone.kr                                      #
########################################################################################################################

output_dir="tmp/C1_LISA"

mkdir -p "$output_dir/System"
mkdir -p "$output_dir/Users"
mkdir -p "$output_dir/Login Shell"
mkdir -p "$output_dir/Logs"
mkdir -p "$output_dir/Crontab"
mkdir -p "$output_dir/IP Tables && Network"
mkdir -p "$output_dir/Process"

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

### System
## file_time_stamp
write_output "find / -path /proc -xdev -prune -o -printf '%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%g;%s;%p\n'" "file_time_stamp.txt" "System"

## 현재 시스템에 로드된 커널 모듈의 목록을 표시
write_output "lsmod" "lsmod.txt" "System"

## 블록 장치(예: 하드 디스크, SSD, USB 드라이브)에 관한 정보
write_output "lsblk" "lsblk.txt" "System"

## 시스템에 연결된 모든 디스크의 파티션 정보
write_output "fdisk -l" "fdisk.txt" "System"

## SystemID
write_output "uname -a" "System_ID.txt" "System"

## Hostname
write_output "hostname" "Hostname.txt" "System"

## 마지막 로그인 시간 수집 
write_output "last -a -i" "Wtmp.txt" "System"

## who 명령어 결과 수집 
write_output "who" "who.txt" "System"

## passwd 파일 수집
write_output "cat /etc/passwd" "passwd.txt" "System"

## shadow 파일 수집 
write_output "cat /etc/shadow" "shadow.txt" "System"

## group 파일 수집
write_output "cat /etc/group" "group.txt" "System"

## hosts 관련 파일 수집 
write_output "cat /etc/hosts" "hosts.txt" "System"
write_output "cat /etc/hosts.allow" "hosts_allow.txt" "System"
write_output "cat /etc/hosts.deny" "host_deny.txt" "System"

## 부팅 관련 파일 수집 
write_output "cat /etc/rc.d/rc.local" "rc_local.txt" "System"
write_output "cat /etc/init.d/rc.local" "init_rc_local.txt" "System"
write_output "cat /etc/rc.d/init.d/rc.local" "rc_init_rc_local.txt" "System"
write_output "cat /etc/init.d/boot.local" "boot_local.txt" "System"

## System Resource
write_output "uptime" "uptime" "System"
write_output "free" "free" "System"
write_output "df -k" "df" "System"

## Find
# dev 폴더의 하위에서 일반적인 파일만 검색
write_output "find /dev -type f -exec file {} \;" "fine_dev.txt" "System"
# 지정한 디렉토리에서 일반적인 파일만 검색하고 자세한 정보 출력
write_output "find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec ls -la {} \;"
# /usr/share 
write_output "find /usr/share -name "*.gz" | xargs file | grep ELF" "find_share.txt" "System"

## Mount
write_output "mount" "mount.txt" "System"

usb_mount_path=$(df -P | awk '$6 ~ /^\/media\/.*[0-9A-Fa-f]/{print $6}')
if [ -n "$usb_mount_path" ]; then
	cp -r "$usb_mount_path" "$output_dir/System"
	echo "[+] Check the USB mount" >> "$output_dir/System/USB_mount.txt"
else
	echo "[-] USB mount not found" >> "$output_dir/System/USB_mount.txt"
fi

## Check
# 각 디렉토리의 자세한 정보 출력
write_output "ls -alR /tmp /dev/shm /var/tm" "System"

# ELF 파일이 어떤 RPM 패키지에 속하는 지 출력
write_output "lsof -F n | awk '/^n/ && /ELF/ {print $2}' | sort -u | while read file; do rpm -qf "$file"; done" "rpm_package.txt" "System"

# 파일 속성 확인
write_output "stat /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin" "binary_file.txt" "System"

# 디버깅 정보가 제거되지 않은 파일 필터링 후 수집
write_output "file /bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/local/bin/* /usr/local/sbin/* | grep 'not strip'" "Check_binary.txt" "System"

# 각 디렉토리에 있는 파일 중 "execu"라는 문자열을 포함하는 파일 수집
write_output "file /lib/* /usr/lib/* /lib64/* /usr/lib64/* /usr/local/lib/* /usr/local/lib64/* | grep 'execu'" "Check_Execute.txt" "System"

## lsof
# 현재 열려 있는 파일들에 대한 정보 출력 ( n 옵션 )
# 현재 열려 있는 네트워크 연결에 대한 정보 출력 ( i 옵션 )
commands=(
	"echo -e -------------------- lsof -n --------------------\n"
	"lsof -n"
	"echo -e \n-------------------- lsof -i --------------------\n"
	"lsof -i"
	)

for command in "${commands[@]}"; do
	write_output "$command" "lsof.txt" "System"
done

### Users
## 사용자 별 History 수집
for user_home in /home/* /root; do
	username=$(basename "$user_home")

	if [ -f "$user_home/.bash_history" ]; then
		write_output "cat $user_home/.bash_history" "bash_command_history_$username.txt" "Users"
	else
		echo "no .bash_history for $username" >> "$output_dir/Users/bash_command_history_$username.txt"
		write_output "cat $user_home/.bash_history" "bash_command_history_$username.txt" "Users"
	fi

	if [ -f "$user_home/.zsh_history" ]; then
		write_output "cat $user_home/.zsh_history" "zsh_command_history_$username" "Users"
	else
		echo "no .zsh_history for $username" >> "$output_dir/Users/zsh_command_history_$username"
		write_output "cat $user_home/.zsh_history" "zsh_command_history_$username" "Users"
	fi

	write_output "cat $user_home/.local/share/recently-used.xbel" "recently_used_files_$username" "Users"
done

## Login Shell
write_output "cat /etc/bash.bashrc" "etc_bashrc.txt" "Login Shell"

for user_login in /home/* ; do
	username=$(basename "$user_login")

	if [ -f "$user_login/.bashrc" ]; then
		write_output "cat $user_login/.bashrc" "bashrc_$username.txt" "Login Shell"
	else
		echo "no .bashrc for $username" >> "$output_dir/Login Shell/bashrc_$username.txt"
		write_output "cat $user_login/.bashrc" "bashrc_$username.txt" "Login Shell"
	fi

	if [ -f "$user_login/.bash_profile" ]; then
		write_output "cat $user_login/.bash_profile" "bash_profile_$username.txt" "Login Shell"
	else
		echo "no .bash_profile for $username" >> "$output_dir/Login Shell/bash_profile_$username.txt"
		write_output "cat $user_login/.bash_profile" "bash_profile_$username.txt" "Login Shell"
	fi

done

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

## cron 수집
for log in /var/spool/cron/crontabs/*; do
	logname=$(basename "$log")
	if [ -f "$log" ]; then
		write_output "cat $log" "$logname.txt" "Crontab"
	else
		echo "No Logfile for $logname" >> "$output_dir/Crontab_file/$logname"
		write_output "cat $log" "$logname.txt" "Crontab"
	fi
done

result_file="/tmp/C1_LISA/forensics_log.txt"

count_success=$(grep -C '^\[+\]' "$result_file")
count_fail=$(grep -C '^\[-\]' "$result_file")

echo "" >> "$logfile"
echo "---------- Number of successful operations: $count_success ----------" >> "$result_file"
echo "----------   Number of failed operations: $count_fail   ----------" >> "$result_file"

grep '^\[-\]' "$result_file" > "/tmp/C1_LISA/failed.txt"

echo "" >> "$logfile"
echo "Forensic data extraction ended at $(date)" >> "$logfile"

echo -e "\e[1;34m\nCompleted!\e[0m"