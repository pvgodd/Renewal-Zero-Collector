#!/bin/bash

##############################################################################################################
#                                        Linux Incident Response Script Renewal-Zero-Collector                #
#                                        Cyberone SOC mss_analysis@cyberon.kr                               #
##############################################################################################################

output_dir="/tmp/c1_Zero_Collector"


mkdir -p "$output_dir/log_file" "$output_dir/cron_file" "$output_dir/System" \
         "$output_dir/IP Tables && Network" "$output_dir/Logs" "$output_dir/Users" \
         "$output_dir/Process"

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

## Collecting_Log_File >>

logs=("secure*" "messages*" "yum*" "dmesg*" "cron*" "auth*" "syslog*" "xferlog*")

for log_pattern in "${logs[@]}"; do
    for log in /var/log/$log_pattern; do
        logname=$(basename "$log")
        if [ -f "$log" ]; then
            write_output "cat $log" "$logname.txt" "Logs"
        else
            echo "No Logfile for $logname" >> "$output_dir/$art_dir/$logname.txt"
        fi
    done
done