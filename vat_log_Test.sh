#!/bin/bash

##############################################################################################################
#                                        Linux Incident Response Script Renewal-Zero-Collector                             #
#                                        Cyberone SOC mss_analysis@cyberon.kr                               #
##############################################################################################################



output_dir="/tmp/c1_Zero_Collector"
mkdir -p "$output_dir/log_file"
mkdir -p "$output_dir/cron_file"
mkdir -p "$output_dir/System"
mkdir -p "$output_dir/IP Tables && Network"
mkdir -p "$output_dir/Logs"
mkdir -p "$output_dir/Users"
mkdir -p "$output_dir/Process"

logfile="$output_dir/forensics_log.txt"


write_output() {
    command=$1
    filename=$2
    art_dir=$3
    if $command >> "$output_dir/$art_dir/$filename" 2>&1; then
        echo "Successfully executed: $command" >> "$logfile"
    else
        echo "Failed to execute: $command" >> "$logfile"
    fi
}


echo "Forensic data extraction started at $(date)" > "$logfile"




## Collecting_History_File >> 

for user_home in /var/log/*; do
    username=$(basename "$user_home")
    
    if [ -f "$user_home/auth.log*" ]; then
        write_output "cat $user_home/auth.log" "$username.txt" "Users"
    else
        echo "No .bash_history for $username" >> "$output_dir/$art_dir/$username.txt" 
    fi

    

done