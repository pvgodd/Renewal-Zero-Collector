### 일반정보

- 배포 버전 표시
cat /etc/*-release

- OS 설치 날짜. 날짜 확인
ls -ld /var/log/installer

### 로그온 

- 특정 키워드로 auth.log에서 로그인 활동 검색하기
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i user
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i Accepted
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i failed
grep -v cron /var/log/auth.log* | grep -v sudo | grep i "login:session"

### 히스토리

- 사용자의 홈 디렉터리에서 이름에 "history"가 포함된 모든 파일을 확인합니다.
cat /home/$USER/.*_history

- 명령 히스토리 확인(bash 셸에만 해당)
cat /home/$USER/.bash_history

- 루트 사용자의 명령 기록을 확인합니다(bash 셸에만 해당).
cat /root/.bash_history

- 루트 사용자에 대한 MySQL 명령 히스토리 확인
cat /root/.mysql_history

- FTP 명령 히스토리 확인 
cat /home/$USER/.ftp_history

- SFTP 명령 히스토리 확인 
cat /home/$USER/.sftp_history

- VIM 편집기 기록 확인 
cat /home/$USER/.viminfo

- 'less' 호출기에 입력한 명령 히스토리 확인 
cat /home/$USER/.lesshst

- Git 설정 확인 
cat /home/$USER/.gitconfig

- 최근 Git 활동 로그 나열 
ls /home/$USER/.git/logs

- Mozilla Firefox 프로필 목록, 기록 및 다운로드 확인
ls /home/$USER/.mozilla/firefox

- Google Chrome 프로필 목록, 기록 및 다운로드 확인
ls /home/$USER/.config/google-chrome

- 인증 로그에서 크론 작업을 제외한 관련 명령을 검색합니다.
grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"



### 특정 문자열 필터링 

- 지난 5일 이내에 수정된 파일을 검색하고 추가 검사를 위해 확인하고 필요한 경우 5를 변경합니다.
find / -type f -mtime -5 | less

- 지난 5일 이내에 수정된 파일 중 이름에 "php"가 포함된 파일을 검색하고 추가 검사를 위해 확인합니다.
find / -type f -mtime -5 | grep "php"

- 지정한 디렉토리에서 지난 10일 동안 수정된 파일을 찾아서 확인합니다.
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10일 전' +'%Y-%m-%d')"

- 지난 하루 동안 수정된 파일을 찾아 경로를 출력합니다.
find / -type f -mtime -1 -print

- 10,000KB보다 큰 파일을 검색하고 경로를 인쇄합니다.
find / -size +10000k -print

- 이노드 번호와 함께 /usr/bin 디렉터리에 있는 파일을 나열하고 숫자순으로 정렬합니다.
ls -lai /usr/bin | sort -n

- 수정 시간순으로 /bin 디렉터리에 있는 파일을 재귀적으로 나열합니다.
ls -laR --sort=time /bin

- setuid 또는 setgid 권한을 가진 루트가 소유한 파일을 찾고 경로를 출력합니다.
find / -user root -perm -04000 -print

/dev 디렉토리에 있는 모든 디바이스를 나열합니다.
ls /dev


### 소프트웨어 패키지 

- 소프트웨어 변경 사항을 추적하기 위해 APT 히스토리 로그에서 패키지 설치에 사용된 명령을 검사합니다.
cat /var/log/apt/history.log | grep "명령줄"

- 소프트웨어 인벤토리 분석을 위해 dpkg 상태 파일에서 패키지 이름과 해당 상태를 검색합니다.
cat /var/lib/dpkg/status | grep -E "Package:|Status:"

- 변경 분석을 위해 설치된 패키지를 나타내는 dpkg 로그 파일에서 항목을 검토합니다.
cat /var/log/dpkg.log | grep installed

- sbin 디렉터리에서 실행 파일을 식별하고 어트리뷰션용 dpkg를 사용하여 패키지 소유권을 확인합니다.
find /sbin/ -exec dpkg -S {} \; | grep "경로를 찾을 수 없음"

- 이상 징후 탐지를 위해 표준 시스템 디렉터리에 있는 실행 파일을 나열합니다.
ls /usr/sbin /usr/bin /bin /sbin

- 다운로드한 패키지를 조사하기 위해 APT 패키지 캐시 디렉터리에 파일을 나열합니다.
ls /var/cache/apt/archives

### 계정

- 잠재적인 권한 상승에 대한 sudo 구성 검토
cat /etc/sudoers

- 백도어에 대한 추가 sudo 구성 확인
cat /etc/sudoers.d/*

- 잠재적인 무단 액세스를 위해 SSH 인증 키를 조사합니다.
cat /home/$USER/.ssh/authorized_keys

- 의심스러운 연결에 대해 SSH 알려진 호스트를 분석합니다.
cat /home/$USER/.ssh/known_hosts

- 사용자 활동에 대해 최근에 사용한 파일 검토
cat /home/$USER/.recently-used.xbel

### 웹쉘 

- var/www/html 디렉토리에서 PHP 파일을 검색하고 수정 타임스탬프를 인쇄합니다.
find /var/www/html -type f -name "*.php" -printf "%T@ %f\n" | sort -n | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2}'

### 크론

- View the configuration of the cron service managed by systemd
cat /lib/systemd/system/cron.service

- etc/cron에 있는 모든 파일 확인
tail -f /etc/cron.*/*

- at 명령으로 예약된 at 작업이 포함된 atjobs 파일의 내용을 봅니다.
cat /var/spool/cron/atjobs

### ssh 데몬

- systemd에서 관리하는 SSH 서비스 구성 보기
cat /lib/systemd/system/ssh.service

- SSH 데몬 구성 파일 보기
cat /etc/ssh/sshd_config

- .ssh 디렉터리에 있는 사용자별 SSH 리소스 파일을 나열합니다.
ls ~/.ssh/rc

- 시스템 전체 SSH 리소스 파일을 /etc/ssh 디렉터리에 나열합니다.
ls /etc/ssh/sshrc

### 감염된 바이너리

- 지정한 디렉터리에서 지난 10일 이내에 수정된 바이너리를 찾습니다. (날짜 사고 시간으로 변경)
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"

- 파이썬 3 관련 라이브러리 및 모듈을 /usr/lib 디렉터리에 나열합니다.
ls /usr/lib/python3*

### 팸 

- Display contents of the PAM configuration file
cat /etc/pam.conf

- Check contents of the PAM directory
cat /etc/pam.d
