# CryptoCrawler
Set of scripts to get list of Cryptos being used in a system

# Prerequisites
- Install sshpass
  - CentOS: sudo yum install sshpass -y
  - SLES: sudo zypper install sshpass -y
- Install python3
  - CentOS: sudo yum install python3 -y
  - SLES: sudo zypper install python3 -y
- Install paramiko
  - pip3 install paramiko

# How to run
- Execute ssh_util.py with help option to get details
  - ./ssh_util.py --help 
- Example runs
  - ./ssh_util.py 10.229.145.152
  - ./ssh_util.py -user core -pwd cycpass 10.229.145.152
