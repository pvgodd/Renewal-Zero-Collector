#!/bin/bash

##############################################################################################################
#                                        Linux Incident Response Script Renewal-Zero-Collector                             #
#                                        Cyberone SOC mss_analysis@cyberone.kr                               #
##############################################################################################################



output_dir="/tmp/c1_Zero_Collector"
mkdir -p "$output_dir/hash" 
mkdir -p "$output_dir/log_file"
mkdir -p "$output_dir/cron_file"

logfile="$output_dir/forensics_log.txt"


write_output() {
    command=$1
    filename=$2
    if $command >> "$output_dir/$filename" 2>&1; then
        echo "Successfully executed: $command" >> "$logfile"
    else
        echo "Failed to execute: $command" >> "$logfile"
    fi
}


echo "Forensic data extraction started at $(date)" > "$logfile"


## HOST

## Storing_System_ID
write_output "uname -a" "Storing_System_ID.txt"

## Storing_Hostname
write_output "hostname" "Storing_Hostname.txt"

## Storing_System_Date
write_output "date " "Storing_System_Date.txt"



## IP Tables && Network

## Storing_IP_Configuration
write_output "ifconfig -a" "Storing_IP_Configuration.txt"

## Storing_Netstat
write_output "netstat -ntulpa" "Storing_Netstat.txt"

## Storing_Routing_Table
write_output "netstat -rn" "Storing_Routing_Table.txt"

## Storing Uptime & W Information
write_output "w" "Storing_W_Information.txt"

## Storing_Iptables_Configuration
write_output "iptables -L" "Storing_Iptables_Configuration.txt"


#### PS

## Storing_Running_Processes
write_output "ps -auxwf" "Storing_Running_Processes_auxwf.txt" "PS"
write_output "ps -ef" "Storing_Running_Processes_ef.txt"

## Check_chkproc
# witre_output "chkproc" "chkproc.txt"

### Check_Del_proc
write_output "find /proc -name maps -exec cat {} \; | grep deleted" "deleted_proc_map.txt"

####


#### login

## Storing WTMP file
write_output "last -a -i" "Storing_WTMP_file.txt"

## Storing Logged Users
write_output "who" "Storing_Logged_Users.txt"

####


#### cat

## /etc/*
write_output "cat /etc/passwd" "Storing_Password_File.txt"
write_output "cat /etc/shadow" "Storing_Shadow_File.txt"
write_output "cat /etc/group" "Storing_Group_File.txt"
write_output "cat /etc/hosts.allow" "Storing_Hosts_allow_File.txt"
write_output "cat /etc/hosts.deny" "Storing_Hosts_deny_File.txt"

##-
write_output "cat /etc/rc.d/rc.local" "cat_rc_local.txt"
write_output "cat /etc/init.d/rc.local" "cat_init_rc_local.txt"
write_output "cat /etc/rc.d/init.d/rc.local" "cat_rc_init_rc_local.txt"
write_output "cat /etc/init.d/boot.local" "cat_init_boot_local.txt"

## /var/log
write_output "cat /etc/rsyncd.conf" "var_log_rsyncd"
write_output "cat /var/log/messages* | grep -i "rsync"" "var_log_message"
write_output "cat /var/log/secure* | grep -i accepte" "var_log_secure_accepte"
write_output "cat /var/log/secure* | grep -i fail" "var_log_secure_fail"

## check syslog
write_output "cat /etc/syslog.conf" "syslog_conf.txt"

# write_output "cat ./result/file_time_stamp.txt | grep -E "tar.gz\$" " 
# write_output "cat ./result/file_time_stamp.txt | grep -E ".tgz\$"  "
# write_output "cat ./result/file_time_stamp.txt | grep -E ".zip\$"  "
write_output "find / -path /proc -xdev -prune -o -printf '%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n' "    "file_time_stamp.txt"

####


## FileSystem
write_output "df -k" "Storing_File_System_Utilization"

## Kernel
write_output "modprobe -l | xargs stat | grep Change >> ./result/ir_result.txt 2>&1" "modprobe.txt" 
write_output "modprobe -l | xargs stat > loaded_all_modules.txt" "modprobe_all_modules.txt"
write_output "modprobe -l >> loaded_all_modules.txt" "modprobe.txt"


## Find
write_output "find /dev -type f -exec file {} \;" "Find_dev.txt"
write_output "find /usr/share -name "*.gz" | xargs file | grep ELF" "find_share.txt"


## mount
write_output "mount" "Mount.txt"
## usbmount
write_output "usb_mount_path=$(df -P | awk '$6 ~ /^\/media\/.*[0-9A-Fa-f]/{print $6}') && [ -n "$usb_mount_path" ] && cp -r "$usb_mount_path" $output_dir/usbmount && echo 'Check the USB mount' || echo "USB mount not found"" "$output_dir/usbmount/USB_Mount.txt"




## Check
witre_output "ls -alR /tmp /dev/shm /var/tm" "ls_tmp_dev_var.txt"




## Check_ELF_File_in_lost
# write_output "rpm -qf `lsof | awk -F ' ' '{print $8}'` | sort | uniq -c | sort | grep file | awk -F ' ' '{print $3}' | xargs file | grep 'ELF'" "rpm_package_8.txt"
# write_output "rpm -qf `lsof | awk -F ' ' '{print $9}'` | sort | uniq -c | sort | grep file | awk -F ' ' '{print $3}' | xargs file | grep 'ELF'" "rpm_package_9.txt"


write_output "lsattr /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin" "binary_file.txt"



## FILE
wirte_output "file /bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/local/bin/* /usr/local/sbin/* | grep 'not strip' " "Check_Binary.txt"
write_output "file /lib/* /usr/lib/* /lib64/* /usr/lib64/* /usr/local/lib/* /usr/local/lib64/* | grep 'execu' " "Check_Execute.txt"



## Collecting_History_File >> 

for user_home in /home/*; do
    username=$(basename "$user_home")
    
    if [ -f "$user_home/.bash_history" ]; then
        write_output "cat $user_home/.bash_history" "bash_command_history_$username.txt"
    else
        echo "No .bash_history for $username" >> "$output_dir/bash_command_history_$username.txt"
    fi
    
    if [ -f "$user_home/.zsh_history" ]; then
        write_output "cat $user_home/.zsh_history" "zsh_command_history_$username.txt"
    else
        echo "No .zsh_history for $username" >> "$output_dir/zsh_command_history_$username.txt"
    fi
    
    write_output "cat $user_home/.local/share/recently-used.xbel" "recently_used_files_$username.txt"
done


# #### check some cmd starace [사용 의미를 몰르겠음]
# write_output "ECHO '[  strace -e trace=open ls -al /abcd  ]' " "starace.txt"
# write_output "strace -e trace=open ls -al /abcd" "starace.txt"

# write_output "ECHO "[  strace -e trace=open find /abcd  ]"" "starace.txt"
# write_output "strace -e trace=open find /abcd" "starace.txt"

# write_output "ECHO "[  strace -e trace=open grep  ]"" "starace.txt"
# write_output "strace -e trace=open grep" "starace.txt"

# write_output "ECHO "[  strace -e trace=open crontab -l  ]"" "starace.txt"
# write_output "strace -e trace=open crontab -l" "starace.txt"

# write_output "ECHO "[  strace -e trace=open su - c1test  ]"" "starace.txt"
# write_output "strace -e trace=open su - c1test" "starace.txt"

# write_output "ECHO "[  strace -e trace=open sudo  ]" " "starace.txt"
# write_output "strace -e trace=open sudo -" "starace.txt"


####

#### Information
write_output "ECHO '[**lsof -n**]'" "losf.txt"
write_output "lsof -n" "losf.txt"
write_output "ECHO '[**lsof -i**]'" "losf.txt"
write_output "lsof -i" "losf.txt"


####

#### copying

## copying /var/log file
write_output "cp /var/log/secure* " "$output_dir/log_file/"
write_output "cp /var/log/messages* " "$output_dir/log_file/"
write_output "cp /var/log/yum* " "$output_dir/log_file/"
write_output "cp /var/log/dmesg* " "$output_dir/log_file/"
write_output "cp /var/log/cron* " "$output_dir/log_file/"
write_output "cp /var/log/auth.log* " "$output_dir/log_file/"
write_output "cp /var/log/syslog* " "$output_dir/log_file/"
write_output "cp /var/log/xferlog* " "$output_dir/log_file/"
write_output "find / -xdev -name pam_unix.so -exec cp {}" "$output_dir/log_file/"

## Copying /var/spool/cron
write_output "cp /var/spool/cron/*" "$logfile/cron_file/"





# ## Storing Failed Logins
# write_output "[ -e /var/log/btmp ] && lastb >> ./result/login_log.txt 2>&1 || echo "***********************************btmp file not found****************************************" >> Storing_Logged_Users.txt 2>&1"
# "if [ -e /var/log/btmp ]
# then 
#     lastb >> ./result/login_log.txt 2>&1
# else
#     echo "***********************************btmp file not found****************************************" >> ./result/login_log.txt 2>&1
# fi"

# ## Storing Inetd.Conf File

# write_output "[ -e /etc/inetd.conf ] && cat /etc/inetd.conf >> ./result/ir_result.txt 2>&1 || $ECHO " INETD.CONF FILE NOT FOUND " >> ./result/ir_result.txt 2>&1
#  "

#  if [ -e /etc/inetd.conf ]
# then
#      $CAT /etc/inetd.conf>> ./result/ir_result.txt 2>&1
# else 
#      $ECHO " INETD.CONF FILE NOT FOUND " >> ./result/ir_result.txt 2>&1
# fi


# tar -czf "$output_dir/user_data.tar.gz" "$output_dir"/*.txt --remove-files

# echo "Data extraction complete. Check the $output_dir directory for output." >> "$logfile"
# echo "Forensic data extraction completed at $(date)" >> "$logfile"

# echo "Data extraction complete. Check the $output_dir directory for output."