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

2024.03.06
- file_stamp 파일 압축 관련
- 주석처리 해 놓은 모듈들 대체 가능한지
- 커널 관련 모듈 modprobe 대체 가능한지

2024.03.07
- LISA update ✔️
- usb mount command update ✔️
- lsof command update ✔️
- result file command 하이라이트
- result file에 [+] [-] 추가 완료 ✔️
- result file에 총합 추가
- 퍼센트 바 추가

2024.03.08
- 퍼센트 바 추가 완료

2024.03.12
- result file command 하이라이트 -> 결과 파일에 적용 불가능
- result file 아티팩트 성공/실패 카운트 수 추가 완료
- 아티팩트 수집 실패 따로 텍스트 파일 저장 완료

2024.04.05
정리하면서 산출물 제작

1. https://fareedfauzi.github.io/2024/03/29/Linux-Forensics-cheatsheet.html#general-information 
명령어 공부 -> 각자 리스트 정리

2. 각자 정리한 리스트 비교

3. LISA Tool과 선정한 리스트 비교

4. Tool 업데이트 

5. 피해 서버 구축 후 Tool 테스트
