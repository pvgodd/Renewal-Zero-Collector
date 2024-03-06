1. 구 버전에서 스크립트를 실행할 때 BPATH가 무조건 다 필요한지
2. 샘플스크립트를 만든 후 여러 구 버전에서 테스트 -> 깃허브 활용


2024.01.09 14:45 
- 한 폴더 내에 이어쓰기
- 분류 별로 폴더 지정
- lib 파일 추가

2024.01.10 ~ //
- centos  6, 5 설치 후 rpm 테스트
- 리눅스 버전 확인 후 rpm 수집 가능하게 소스코드 수정
- write_output "lsattr /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin" "binary_file.txt" -> bin 폴더 없어서 에러남
- lsof -n이랑 -i 옵션 한 파일에 저장 및 구분할 수 있게 수정
- write_output copy 명령어 되는지 확인
