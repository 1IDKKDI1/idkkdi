#!/bin/bash

# ^M delimitor error solution
# sed -i 's/\r//g' information_linux.sh
HOSTNAME=`hostname`
LANG=C
export LANG
clear
BUILD_VER=1.0.1
LAST_UPDATE=2024.03.21
WRITER=super-cert
CREATE_FILE=`hostname`.txt
# CREATE_FILE=`hostname`_Linux_`date +%y-%m-%d`.txt
FLAG_TABLE=("DEFAULT" N Y M "N/A")


#:set ff=unix


echo "" > $CREATE_FILE 2>&1ef
echo "###################################################################" >> $CREATE_FILE 2>&1
echo "    Copyright (c) 2024 SECURITY Co. Ltd. All Rights Reserved.       " >> $CREATE_FILE 2>&1
echo "     LINUX Vulnerability Check Version $BUILD_VER ($LAST_UPDATE)   " >> $CREATE_FILE 2>&1
echo "###################################################################" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


echo "###########################  LINUX Security Check-v${BUILD_VER}  #############################"
echo "###########################  LINUX Security Check-v${BUILD_VER}  #############################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "##################################  Start Time  #######################################"
date
echo "##################################  Start Time  #######################################" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=========================== System Information Query Start ============================"
echo "=========================== System Information Query Start ============================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "############################### HostName ###############################"
echo "############################### HostName ###############################" >> $CREATE_FILE 2>&1
hostname                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###############################  Kernel Information  ##################################"
echo "###############################  Kernel Information  ##################################" >> $CREATE_FILE 2>&1
uname -a                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################## IP Information #####################################"
echo "################################## IP Information #####################################" >> $CREATE_FILE 2>&1
ifconfig -a                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################  Network Status(1) ###################################"
echo "################################  Network Status(1) ###################################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED"                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Network Status(2) ##################################"
echo "################################   Network Status(2) ##################################" >> $CREATE_FILE 2>&1
netstat -nap | egrep -i "tcp|udp"                                                              >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#############################   Routing Information   #################################"
echo "#############################   Routing Information   #################################" >> $CREATE_FILE 2>&1
netstat -rn                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Process Status   ###################################"
echo "################################   Process Status   ###################################" >> $CREATE_FILE 2>&1
ps -ef                                                                                         >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###################################   User Env   ######################################"
echo "###################################   User Env   ######################################" >> $CREATE_FILE 2>&1
env                                                                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=========================== System Information Query End =============================="
echo "=========================== System Information Query End ==============================" >> $CREATE_FILE 2>&1

################################## os check ###################################

os_check=`cat /etc/*-release | grep "Oracle Solaris" | wc -c`
if ! [ $os_check -eq 0 ]
then
	echo "OS => SOLARIS"
	os_version=1
	os_category="solaris"
else
	echo "OS => LINUX"
	os_version=2
	os_category="linux"
fi 


if [ $os_version -eq 1 ]
then
	cp /dev/null solaris_command_list.txt
		COMMDD="inetadm svcs svcadm"

		for commdo in $COMMDD
		do
		    which $commdo                                                                         >> solaris_command_list.txt
		done	
fi
############################### APACHE Check Process Start(linux) ##################################

#0. 필요한 함수 선언

apache_awk() {
	if [ `ps -ef | grep -i $1 | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
	then
		apaflag=8
	elif [ `ps -ef | grep -i $1 | grep -v "ns-httpd" | grep -v "grep" | awk '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
	then
		apaflag=9
	fi
}

# 솔라리스 부분 추가 필요

# 1. 아파치 프로세스 구동 여부 확인 및 아파치 TYPE 판단, awk 컬럼 확인

if [ `ps -ef | grep -i "httpd" | grep -v "ns-httpd" | grep -v "lighttpd" | grep -v "grep" | wc -l` -gt 0 ]
then
	apache_type="httpd"
	apache_awk $apache_type

elif [ `ps -ef | grep -i "apache2" | grep -v "ns-httpd" | grep -v "lighttpd" | grep -v "grep" | wc -l` -gt 0 ]
then
	apache_type="apache2"
	apache_awk $apache_type
else
	apache_type="null"
	apaflag=0	
fi


# 2. 아파치 홈 디렉토리 경로 확인
if [ ! $os_version -eq 1 ]
then
	

	if [ $apaflag -ne 0 ]
	then

		if [ `ps -ef | grep -i $apache_type | grep -v "ns-httpd" | grep -v "grep" | awk -v apaflag2=$apaflag '{print $apaflag2}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
		then
			
			APROC1=`ps -ef | grep -i $apache_type | grep -v "ns-httpd" | grep -v "grep" | awk -v apaflag2=$apaflag '{print $apaflag2}' | grep "/" | grep -v "httpd.conf" | uniq`
			APROC=`echo $APROC1 | awk '{print $1}'`
			$APROC -V > APROC.txt 2>&1
			
			ACCTL=`echo $APROC | sed "s/$apache_type$/apachectl/"`
			$ACCTL -V > ACCTL.txt 2>&1
			
			if [ `cat APROC.txt | grep -i "root" | wc -l` -gt 0 ]
			then
				
				AHOME=`cat APROC.txt | grep -i "root" | awk -F"\"" '{print $2}'`
				ACFILE=`cat APROC.txt | grep -i "server_config_file" | awk -F"\"" '{print $2}'`
			else
				
				AHOME=`cat ACCTL.txt | grep -i "root" | awk -F"\"" '{print $2}'`
				ACFILE=`cat ACCTL.txt | grep -i "server_config_file" | awk -F"\"" '{print $2}'`
			fi
		fi
		
		if [ -f $AHOME/$ACFILE ]
		then
		
			ACONF=$AHOME/$ACFILE
		else
		
			ACONF=$ACFILE
		fi	
	fi

else # solaris
	cp /dev/null apache_dir.txt
	if [ `ps -ef | grep httpd | grep -v grep | wc -l` -ge 1 ]; then 
	      
	      if [ `ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $8}' | grep http | wc -l` -ge 1 ];then
	      		
	          ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $8}' | grep httpd          >> apache_dir.txt
	          webdir=`cat -n apache_dir.txt | head -n 1 | awk -F' ' '{print $2}'`
	          AHOME=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
	          conf=`$webdir -V | grep "SERVER_CONFIG_FILE" |  awk -F'"' '{print $2}'`
	          if [ -f $conf ]; then
	              ACONF=$conf
	        else
	            ACONF="$AHOME/$conf"
	            

	      fi
	        docroot=`cat $ACONF | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
	        echo "################################## WEB설정 정보 #################################"              >> $CREATE_FILE 2>&1
	        ls -al $ACONF                                                                                             >> $CREATE_FILE 2>&1
	        cat $ACONF                                                                                             >> $CREATE_FILE 2>&1
	        echo " "                                                                                              >> $CREATE_FILE 2>&1
	        
	    else
	        ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $9}' | grep httpd          >> apache_dir.txt
	        webdir=`cat -n apache_dir.txt | head -n 1 | awk -F' ' '{print $2}'`
	        AHOME=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
	        conf=`$webdir -V | grep "SERVER_CONFIG_FILE" |  awk -F'"' '{print $2}'`
	        if [ -f $conf ]; then
	            ACONF=$conf
	        else
	            ACONF="$AHOME/$conf"
	      fi
	        docroot=`cat $ACONF | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
	        echo "################################## WEB설정 정보 #################################"              >> $CREATE_FILE 2>&1
	        ls -al $ACONF                                                                                             >> $CREATE_FILE 2>&1
	        cat $ACONF                                                                                             >> $CREATE_FILE 2>&1	
	        echo " "                                                                                              >> $CREATE_FILE 2>&1
	        
	    fi
	fi

fi 

rm -rf apache_dir.txt

######################################### 아파치 (solaris) ########################################


#아파치 변수 셋팅
if [ `ps -ef | grep httpd | grep -v lighttpd | grep -v grep | wc -l` -ge 1 ]; then 
      
      if [ `ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $8}' | grep http | wc -l` -ge 1 ];then
          ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $8}' | grep httpd          >> apache_dir.txt
          webdir=`cat -n apache_dir.txt | head -n 1 | awk -F' ' '{print $2}'`
          apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
          ACONF=`$webdir -V | grep "SERVER_CONFIG_FILE" |  awk -F'"' '{print $2}'`
          if [ -f $ACONF ]; then
              ACONF=$ACONF
        else
            ACONF="$apache/$ACONF"
      fi
        docroot=`cat $ACONF | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
        echo "################################## WEB설정 정보 #################################"              >> $CREATE_FILE 2>&1
        cat $ACONF                                                                                             >> $CREATE_FILE 2>&1
        echo " "                                                                                              >> $CREATE_FILE 2>&1
        
    else
        ps -ef | grep httpd | grep -v grep | awk -F' ' '{print $9}' | grep httpd          >> apache_dir.txt
        webdir=`cat -n apache_dir.txt | head -n 1 | awk -F' ' '{print $2}'`
        apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
        ACONF=`$webdir -V | grep "SERVER_CONFIG_FILE" |  awk -F'"' '{print $2}'`
        if [ -f $ACONF ]; then
            ACONF=$ACONF
        else
            ACONF="$apache/$ACONF"
      fi
        docroot=`cat $ACONF | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
        echo "################################## WEB설정 정보 #################################"              >> $CREATE_FILE 2>&1
        cat $ACONF                                                                                             >> $CREATE_FILE 2>&1
        echo " "                                                                                              >> $CREATE_FILE 2>&1
        
    fi
fi

rm -rf apache_dir.txt


# echo $AHOME
# echo $ACFILE
# echo $ACONF
# cat $ACONF | grep -i "^user"                                                                 

# 3. 불필요한 파일 삭제

rm -rf APROC.txt
rm -rf ACCTL.txt



################################ APACHE Check Process End ###################################

################################ SSH Check Process Start ####################################


if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -gt 0 ]
then
	sshd_flag=1 # enable

else
	sshd_flag=0 # disable
fi

ps -ef | grep sshd | grep -v "grep" > sshd_ps_ef.txt
################################ SSH Check Process End  ####################################

################################ TELNET Check Process Start #################################

echo "● TELNET 서비스 포트 활성화 여부 확인"                                                          >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		echo "☞ Telnet Service Enable"                                                           >> $CREATE_FILE 2>&1
		netstat -na | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                           >> $CREATE_FILE 2>&1
	else
		echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
	fi
fi

################################ TELNET Check Process End ###################################

################################ FTP Check Process Start ###################################

find /etc -name "proftpd.conf" | grep "/etc/"                                                     > proftpd.txt
find /etc -name "vsftpd.conf" | grep "/etc/"                                                      > vsftpd.txt
profile=`cat proftpd.txt`
vsfile=`cat vsftpd.txt`
# ftpinfo.txt
echo "① /etc/services 파일에서 포트 확인"                                                     > ftpinfo.txt
echo "------------------------------------------------------------------------------"          >> ftpinfo.txt
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> ftpinfo.txt
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> ftpinfo.txt
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> ftpinfo.txt
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> ftpinfo.txt
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> ftpinfo.txt
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> ftpinfo.txt
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> ftpinfo.txt
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> ftpinfo.txt
fi
echo " "                                                                                       >> ftpinfo.txt
echo "② 서비스 포트 활성화 여부 확인"                                                         >> ftpinfo.txt
echo "------------------------------------------------------------------------------"          >> ftpinfo.txt

if [ ! $os_version -eq 1 ]
then
	################# /etc/services 파일에서 포트 확인 #################
	if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
		then
			netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> ftpinfo.txt
			echo "enable"                                                                                   > ftpenable.txt
		fi
	else
		netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> ftpinfo.txt
		echo "enable"                                                                                     > ftpenable.txt
	fi
	################# vsftpd 에서 포트 확인 ############################
	if [ -s vsftpd.txt ]
	then
		if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
		then
			port=21
		else
			port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
		fi
		if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
		then
			netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> ftpinfo.txt
			echo "enable"                                                                                   > ftpenable.txt
		fi
	fi
	################# proftpd 에서 포트 확인 ###########################
	if [ -s proftpd.txt ]
	then
		port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
		if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
		then
			netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> ftpinfo.txt
			echo " "                                                                                   > ftpenable.txt
		fi
	fi
else # solaris

    ################# /etc/services 파일에서 포트 확인 #################

    if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
      then
          port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
          
          if [ `netstat -na | grep ".$port " | grep -i "LISTEN" | wc -l` -gt 0 ]
            then
                netstat -na | grep ".$port " | grep -i "LISTEN"                                                 >> ftpinfo.txt
                echo "enable"                                                           > ftpenable.txt
          fi
      else
          netstat -na | grep ".21 " | grep -i "LISTEN"                                                          >> ftpinfo.txt
          echo "enable"                                                                 > ftpenable.txt
    fi

    ################# vsftpd 에서 포트 확인 ############################

    if [ -s vsftpd.txt ]
      then
          if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
            then
                port=21
            else
                port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
          fi
          if [ `netstat -na | grep ".$port " | grep -i "LISTEN" | wc -l` -gt 0 ]
            then
                netstat -na | grep ".$port " | grep -i "LISTEN"                                                 >> ftpinfo.txt
                echo "enable"                                                           >> ftpenable.txt
          fi
        else
          echo "disable"                                                                >> ftpenable.txt
    fi

    ################# proftpd 에서 포트 확인 ###########################

    if [ -s proftpd.txt ]
      then
          port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
          
          if [ `netstat -na | grep ".$port " | grep -i "LISTEN" | wc -l` -gt 0 ]
            then
                netstat -na | grep ".$port " | grep -i "LISTEN"                                                 >> ftpinfo.txt
                echo "enable"                                                           >> ftpenable.txt
              else
                echo "disable"                                                          >> ftpenable.txt
          fi
        else
          echo "disable"                                                                >> ftpenable.txt
    fi


fi 


################################ FTP Check Process End ###################################
###

rootuser=`awk -F: '$3==0 { print $1 }' /etc/passwd` # uid=0 계정 체크

###
U_01() {
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************** START *****************************************"
echo "*************************************** START *****************************************" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "###########################        1. 계정 관리        ################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "[U-1 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.1 root 계정 원격 접속 제한 #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.1 root 계정 원격 접속 제한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한경우"       >> $CREATE_FILE 2>&1 
echo "■ 기준1: [telnet] /etc/securetty 파일에 pts/* 설정이 있으면 무조건 취약"                          >> $CREATE_FILE 2>&1 
echo "■ 기준2: [telnet] /etc/securetty 파일에 pts/* 설정이 없거나 주석처리가 되어 있고,"                >> $CREATE_FILE 2>&1 
echo "■        : /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#)이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 기준3: [SSH] /etc/ssh/sshd_config 파일에 PermitRootLogin no로 설정되어 있을 경우 양호"       >> $CREATE_FILE 2>&1 
echo "■ /etc/sshd/sshd_config 에 값이 없으면 root로 ssh login 가능"       >> $CREATE_FILE 2>&1 
echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① [telnet] /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② [telnet] 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_01_flag=0
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	if [ ! $os_version -eq 1 ] 
		then
			if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
			then
				netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
				flag1=M
			else
				echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
				flag1="Disabled"
			fi
		else # solaris
			
			if [ `netstat -na | grep "\.$port   " | egrep "LISTEN|IDLE|ESTABLISHED" | wc -l` -gt 0 ]
			then
				netstat -na | grep "\.$port   " | egrep "LISTEN|IDLE|ESTABLISHED"                                              >> $CREATE_FILE 2>&1
				flag1=M
			else
				echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
				flag1="Disabled"
			fi
		fi
fi

if [ ! $os_version -eq 1 ]
then
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ [telnet] /etc/securetty 파일 설정"                                                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/securetty ]
	then
		if [ `cat /etc/securetty | grep -v "^#" | grep "pts" | wc -l` -gt 0 ]
		then
			cat /etc/securetty | grep "pts"                                                              >> $CREATE_FILE 2>&1
			u_01_flag=1
			echo " "                                  												   >> $CREATE_FILE 2>&1
			echo "pts/0~pts/x 설정이 있습니다 (취약)"                    					                >> $CREATE_FILE 2>&1
		else
			echo "/etc/securetty 파일에 pts/0~pts/x 설정이 없습니다."                                    >> $CREATE_FILE 2>&1
		fi
	else 
		echo "/etc/securetty 파일이 없습니다."                                    >> $CREATE_FILE 2>&1
	fi 
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "④ [telnet] /etc/pam.d/login 파일 설정"                                                           >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	cat /etc/pam.d/login | grep "pam_securetty.so"                                                 >> $CREATE_FILE 2>&1
	if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep "^#" | wc -l` -ne 0 ]
	then
		echo " "                                  												   >> $CREATE_FILE 2>&1
		echo "securetty가 주석입니다 (취약) "                    					                >> $CREATE_FILE 2>&1
		let u_01_flag=$u_01_flag1+1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
else # solaris
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ [telnet] /etc/default/login 파일 설정"                                                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/default/login ]
	then
		if [ `cat /etc/default/login | grep -v "^#" | grep "CONSOLE=/dev/console" | wc -l` -gt 0 ]
		then
			cat /etc/default/login | grep -v "^#" | grep "CONSOLE=/dev/console"                                >> $CREATE_FILE 2>&1
			
			echo " "                                  												   >> $CREATE_FILE 2>&1
		else
			u_01_flag=1
			echo "/etc/default/login 에 설정이 없습니다 (취약)"                                    >> $CREATE_FILE 2>&1
		fi
	else 
		echo "/etc/default/login 파일이 없습니다."                                    >> $CREATE_FILE 2>&1
	fi 
fi 	

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "⑤ [SSH] 서비스 구동 확인"                                                               >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
if [ $sshd_flag -eq 0 ]
then
  echo "☞ SSH Service Disable"                                                         >> $CREATE_FILE 2>&1

else
  cat sshd_ps_ef.txt                                                         >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


if [ $sshd_flag -eq 1 ]
then
	echo "⑥ [SSH] /opt/ssh/etc/sshd_config 파일 확인 " >> $CREATE_FILE 2>&1
	echo "--------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
	if [ `cat /etc/ssh/sshd_config | egrep -i 'PermitRootLogin' | wc -l` -eq 0 ]
	then
		
		echo "sshd_config 파일 설정이 안되어 있습니다. (취약) " >> $CREATE_FILE 2>&1
		let u_01_flag=$u_01_flag1+1
	else
		cat /etc/ssh/sshd_config | egrep -i 'PermitRootLogin'	                              >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		if [ `cat /etc/ssh/sshd_config | grep -v "^#" | egrep -i 'PermitRootLogin' | grep -i 'no' | wc -l` -eq 0 ]
		then
			let u_01_flag=$u_01_flag1+1
			echo "root 접속이 가능합니다 (취약) " >> $CREATE_FILE 2>&1

	  	else 
			echo "root 접속이 불가합니다" >> $CREATE_FILE 2>&1					
	  	fi 
	cat /etc/ssh/sshd_config | grep -v "^#" | egrep -i 'PermitRootLogin' | >> $CREATE_FILE 2>&1
	fi	
fi 
if [ $u_01_flag -gt 0 ]
then
	echo [결과] N                                                          >> $CREATE_FILE 2>&1	
else
	echo [결과] Y                                                          >> $CREATE_FILE 2>&1	
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-1 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_02() {
echo "[U-2 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.2 패스워드 복잡성 설정 ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.2 패스워드 복잡성 설정              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우"                                        >> $CREATE_FILE 2>&1 
echo "centos 8 ge : /etc/security/pwquality.conf"                                        >> $CREATE_FILE 2>&1 
echo "centos 7 le : /etc/pam.d/system-auth"                                        >> $CREATE_FILE 2>&1 
echo "aix : /etc/security/user"                                        >> $CREATE_FILE 2>&1 
echo "hp_ux : /etc/default/security"                                        >> $CREATE_FILE 2>&1 
echo "solaris 10 : /etc/default/passwd"                                        >> $CREATE_FILE 2>&1 
echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
u_02_flag=3

# os version
echo "[os version]"                                                                      >> $CREATE_FILE 2>&1
echo " "                                                                      >> $CREATE_FILE 2>&1
#echo $os_version                                                                      >> $CREATE_FILE 2>&1
cat /etc/*-release                                                                      >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
# centos 8 morethan
if [ -f /etc/security/pwquality.conf ]
then
	echo "[centos 8 more than]"                                                                      >> $CREATE_FILE 2>&1
	echo "pwquality.conf"                                                                      >> $CREATE_FILE 2>&1
	cat /etc/security/pwquality.conf  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
fi

# centos 7 less than
if [ -f /etc/pam.d/system-auth ]
then
	echo "[centos 7 le]"                                                                      >> $CREATE_FILE 2>&1
	echo "/etc/pam.d/system-auth"                                                                      >> $CREATE_FILE 2>&1
	cat /etc/pam.d/system-auth  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
fi

# aix
if [ -f /etc/security/user ]
then
	echo "[aix]"                                                                      >> $CREATE_FILE 2>&1
	echo "/etc/security/user"                                                                      >> $CREATE_FILE 2>&1
	cat /etc/security/user  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
fi

# hp_ux
if [ -f /etc/default/security ]
then
	echo "[hp_ux]"                                                                      >> $CREATE_FILE 2>&1
	echo "/etc/default/security"                                                                      >> $CREATE_FILE 2>&1
	cat /etc/default/security  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
fi

# solaris 
if [ $os_version -eq 1 ]
then
	if [ -f /etc/default/passwd ]
	then
		echo "[solaris 10 more than]"                                                                      >> $CREATE_FILE 2>&1
		echo "/etc/default/passwd"                                                                      >> $CREATE_FILE 2>&1
		cat /etc/default/passwd  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
		echo "----------------------------------------------"        >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/pam.d/passwd ]
	then		
		echo "/etc/pam.d/passwd"                                                                      >> $CREATE_FILE 2>&1
		cat /etc/pam.d/passwd  | grep -v "^#"                                                                     >> $CREATE_FILE 2>&1
		if [ `cat /etc/pam.d/passwd | grep -v "^#" | grep "require" | grep "pam_passwd_auth" | wc -l` -gt 0 ]
		then
			echo " "                                  >> $CREATE_FILE 2>&1
			echo "복잡성 설정이 되어 있습니다 (pam_passwd_auth)"                                  >> $CREATE_FILE 2>&1
			u_02_flag=2
		fi


	fi
fi
echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1

# authconfig --test | grep password   >> $CREATE_FILE 2>&1


echo [결과] ${FLAG_TABLE[$u_02_flag]}          	                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-2 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_03() {
echo "[U-3 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.3 계정 잠금 임계값 설정 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            1.3 계정 잠금 임계값 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/pam.d/system-auth 파일에 아래와 같은 설정이 있으면 양호"                    >> $CREATE_FILE 2>&1
echo "■       : (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)" >> $CREATE_FILE 2>&1
echo "■       : (account required /lib/security/pam_tally.so no_magic_root reset)"             >> $CREATE_FILE 2>&1
echo "계정 잠금 임계값 설정 TIP" 												>> $CREATE_FILE 2>&1
echo "계정 임계값을 설정하려면 pam_tally.so 라는 라이브러리를 사용하는데 리눅스 버전에 따라서" >> $CREATE_FILE 2>&1 
echo "pam_tally.so[구버전]  pam_tally2.so[신버전] 에 설치되어있으므로 해당 버전에 맞도록 설정해야한다." >> $CREATE_FILE 2>&1 
echo "telnet 의 경우 /etc/pam.d/remote 에 설정을 한다."                                                  >> $CREATE_FILE 2>&1 
echo "ssh 의 경우 /etc/pamd.d/sshd 에 설정을 한다. "                                                   >> $CREATE_FILE 2>&1 
echo "ftp 의 경우 /etc/pamd.d/ftp 에 설정을 한다.[SFTP경우 ssh정책을따름]"        >> $CREATE_FILE 2>&1
echo "위 파일에 다음과 같은 설정을 해주어야한다."                        >> $CREATE_FILE 2>&1 
echo "예시] vi /etc/pam.d/sshd"                                          >> $CREATE_FILE 2>&1             
echo "예시] auth  required  pam_tally.so  onerr=fail  deny=5  unlock_time=1800  no_magic_root  reset"  >> $CREATE_FILE 
echo "예시] account  required  pam_tally.so  no_magic_root"            >> $CREATE_FILE 2>&1 
echo "위의 예시에서 pam_tally2를 사용한다면 pam_tally2.so 를 명시한다."  >> $CREATE_FILE 2>&1 
echo "onerr=fail  : 오류가 발생하면 접근 차단"                            >> $CREATE_FILE 2>&1
echo "deny=5 : 5번의 임계값을 가짐 [이후 계정 잠김]"                      >> $CREATE_FILE 2>&1
echo "unlock_time=120 : 계정 잠김 후 2분 이후 잠김 해제" 				>> $CREATE_FILE 2>&1
echo "no_magic_root : root 계정은 잠기지 않도록 설정"                        >> $CREATE_FILE 2>&1
echo "reset : 로그인이 성공하면 badcount 값 reset됨"                           >> $CREATE_FILE 2>&1
echo "잠금설정을 강제로 초기화 하고싶다면 다음과같이 설정한다"                 >> $CREATE_FILE 2>&1
echo "pam_tally2 사용시 = pam_tally2 -u [username] -r"                        >> $CREATE_FILE 2>&1
echo "pam_tally 사용시 = faillog -u [username] -r" 												>> $CREATE_FILE 2>&1
echo "해당항목들을 설정파일에서 찾을수 없다면 취약함"                             >> $CREATE_FILE 2>&1
echo "운용중인 서버에서 이 정책을 반영할경우 주의해야 하는건 설정을 잘못하면 root 계정 및 일반계정이 잠김으로" >> $CREATE_FILE 2>&1
echo "엔지니어와 함께 정책을 반영하고 최소 한개의 세션은 root 권한으로 접속을 유지시킨뒤 작업완료 여부를 확인한후 적용한다" >> $CREATE_FILE 2>&1 

echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1

u_03_flag=0

if [ ! $os_version -eq 1 ]
then
	if [ -f /etc/pam.d/system-auth ] #RHEL su 전환 또는 콘솔 로그인
	then
		u_03_flag=3
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		echo "☞ /etc/pam.d/system-auth 파일 설정(auth, account)"                                    >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
		egrep "auth|account" /etc/pam.d/system-auth                                                  >> $CREATE_FILE 2>&1
			if [ `egrep "auth|account|include" /etc/pam.d/system-auth | grep -v "#" | grep "deny=" | wc -l` -ne 0 ] # deny 설정
			then
				
				deny_num=`echo egrep "auth|account|include" /etc/pam.d/system-auth | grep -v "#" | grep deny= | sed -n 's/.*deny=\([0-9]*\) .*/\1/p'`
				echo " "                     >> $CREATE_FILE 2>&1
				if [ $deny_num -le 5 -a $deny_num -ne 0 ]
					then
						u_03_flag=2
						echo "정책이 제대로 설정 되있습니다 "                     >> $CREATE_FILE 2>&1

					else
						echo "정책이 제대로 설정 되어있지 않습니다. (취약)"                     >> $CREATE_FILE 2>&1
						u_03_flag=1
				fi
			else
				u_03_flag=1
				echo "정책이 제대로 설정 되어있지 않습니다. (취약)"                     >> $CREATE_FILE 2>&1
			fi 
	elif [ -f /etc/pam.d/common-auth ] # LINUX - UBUNTU
		then
			u_03_flag=3
			echo " "                                                                                   >> $CREATE_FILE 2>&1
			echo "☞ /etc/pam.d/common-auth 파일 설정(auth, account, include)"                         >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
			egrep "auth|account|include" /etc/pam.d/common-auth | grep -v "#"                          >> $CREATE_FILE 2>&1

			if [ `cat /etc/pam.d/common-auth | egrep "auth|account|include" | grep -v "#" | grep "deny=" | wc -l` -ne 0 ] # deny 설정
			then
				
				deny_num=`egrep "auth|account|include" /etc/pam.d/common-auth | grep -v "#" | grep "deny=" | sed -n 's/.*deny=\([0-9]*\) .*/\1/p'`
				echo " "                     >> $CREATE_FILE 2>&1
				if [ $deny_num -le 5 -a $deny_num -ne 0 ]
				then
						u_03_flag=2
						echo "정책이 제대로 설정 되있습니다 "                     >> $CREATE_FILE 2>&1

				else
						u_03_flag=1
						echo "정책이 제대로 설정 되어있지 않습니다"                     >> $CREATE_FILE 2>&1
				fi
			fi 
	fi


	if [ -f /etc/pam.d/password-auth ] # LINUX - xwindows, ssh 원격 접속 시 설정 
		then
			u_03_flag=3
			echo " "                                                                                   >> $CREATE_FILE 2>&1
			echo "☞ /etc/pam.d/password-auth 파일 설정(auth, account, include)"                         >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
			egrep "auth|account|include" /etc/pam.d/password-auth | grep -v "#"                          >> $CREATE_FILE 2>&1

			if [ `cat /etc/pam.d/password-auth | egrep "auth|account|include" | grep -v "#" | grep "deny=" | wc -l` -ne 0 ] # deny 설정
			then
				
				deny_num=`egrep "auth|account|include" /etc/pam.d/password-auth | grep -v "#" | grep "deny=" | sed -n 's/.*deny=\([0-9]*\) .*/\1/p'`
				echo " "                     >> $CREATE_FILE 2>&1
				if [ $deny_num -le 5 -a $deny_num -ne 0 ]
				then
						u_03_flag=2
						echo "정책이 제대로 설정 되있습니다 "                     >> $CREATE_FILE 2>&1

				else
						u_03_flag=1
						echo "정책이 제대로 설정 되어있지 않습니다"                     >> $CREATE_FILE 2>&1
				fi
			fi 
		
	fi


		echo " "                                                                                     >> $CREATE_FILE 2>&1
		echo "☞ /etc/pam.d/sshd 파일 설정(auth, account, include)"                                           >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1

		egrep "auth|account|include" /etc/pam.d/sshd | grep -v "#"                                   >> $CREATE_FILE 2>&1
	echo " "                     >> $CREATE_FILE 2>&1
else # solaris
	US_03_FILE="/etc/security/policy.conf"
	if [ -f $US_03_FILE ]
	then
		cat $US_03_FILE | grep -v "^$" | grep "LOCK_AFTER_RETRIES=YES"            >> $CREATE_FILE 2>&1
		if [ `cat $US_03_FILE | grep -v "^$" | grep -v "^#" | grep "LOCK_AFTER_RETRIES=YES" | wc -l` -eq 0 ]
			then
				echo "LOCK_AFTER_RETRIES=YES 설정이 없습니다 (취약)"                >> $CREATE_FILE 2>&1
				u_03_flag=1
			else
				cat /etc/default/login | grep "^RETRIES"             >> $CREATE_FILE 2>&1
				if [ `cat /etc/default/login | grep -v "^#" | grep "RETRIES" | wc -l` -eq 0 ]
					then 
						echo "기본 임계 값은 5회"                              >> $CREATE_FILE 2>&1
						u_03_flag=2

				else
					
					if [ `cat /etc/default/login | grep -v "#"| grep "RETRIES" | awk -F'=' '{print $2}' | xargs` -gt 10 ] 
						then
						echo "계정 잠금 임계값이 10회를 넘습니다"                              >> $CREATE_FILE 2>&1
						u_03_flag=1
					else
						u_03_flag=2
					fi
				fi
		fi


	else
		echo "$US_03_FILE 이 없습니다"                             >> $CREATE_FILE 2>&1

	fi
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $u_03_flag == 2 ]
then
	echo [결과] Y      			                                                                 >> $CREATE_FILE 2>&1
elif [ $u_03_flag == 1 ]
	then
	echo [결과] N      			                                                                 >> $CREATE_FILE 2>&1
else
	echo [결과] M      			                                                                 >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-3 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_04() {
echo "[U-4 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.4 패스워드 파일 보호 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.4 패스워드 파일 보호               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"                  >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
echo "패스워드 파일 보호 TIP" 																>> $CREATE_FILE 2>&1
echo "패스워드 해쉬값이 /etc/passwd 존재한다면 취약함"            								>> $CREATE_FILE 2>&1
echo "또한 /etc/shadow 파일의 권한이 그외사용자가 읽거나 쓰기가 가능해도 취약함"  				>> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1

echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]
	then
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있지 않습니다."                         >> $CREATE_FILE 2>&1
		echo " "     	                                                                                 >> $CREATE_FILE 2>&1
		echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1

	else
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있습니다. "                              >> $CREATE_FILE 2>&1
		echo " "     	                                                                                 >> $CREATE_FILE 2>&1
		echo "두번 째 자리가 x로 표현됩니다"          	                                                                 >> $CREATE_FILE 2>&1
		echo " "     	                                                                                 >> $CREATE_FILE 2>&1
		echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
	fi
else
	echo "☞ /etc/passwd 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
	echo " "     	                                                                                 >> $CREATE_FILE 2>&1
	echo [결과] M          	                                                                 >> $CREATE_FILE 2>&1
fi
echo " "     	                                                                                 >> $CREATE_FILE 2>&1
echo "[U-4 End]"                                                                              >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_44() {
echo "[U-44 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.5 root 이외의 UID가 '0' 금지 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          1.5 root 이외의 UID가 '0' 금지           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: root 계정만이 UID가 0이면 양호"                                                  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1


u_44_flag=0
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd > u_44.txt
    cat u_44.txt                                     >> $CREATE_FILE 2>&1
    u_44_flag=`cat u_44.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
  else
    echo "☞ /etc/passwd 파일이 존재하지 않습니다."                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "UID=0 인 개수: "`cat u_44.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'` 												 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $u_44_flag -gt 1 ]
then
	echo "UID 0 인 계정이 2개 이상입니다"                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] N 												 >> $CREATE_FILE 2>&1	
elif [ $u_44_flag -eq 1 ]
then
	echo [결과] Y 												 >> $CREATE_FILE 2>&1	
else

	echo [결과] M 												 >> $CREATE_FILE 2>&1	
fi 
echo " "                                                                                       >> $CREATE_FILE 2>&1

rm -rf u_44.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-44 End]"                                                                                >> $CREATE_FILE 2>&1
# echo "☞ /etc/passwd 파일 내용"                                                                >> $CREATE_FILE 2>&1
# echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
# cat /etc/passwd                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_45() {
echo "[U-45 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.6 root 계정 su 제한 ##############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.6 root 계정 su 제한               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준1: /etc/pam.d/su 파일 설정이 아래와 같을 경우 양호"                                >> $CREATE_FILE 2>&1
echo "■ 기준2: 아래 설정이 없거나, 주석 처리가 되어 있을 경우에는 su 명령 파일의 권한이 4750 이면 양호" >> $CREATE_FILE 2>&1
echo "■        : (auth  required  /lib/security/pam_wheel.so debug group=wheel) 또는"          >> $CREATE_FILE 2>&1
echo "■        : (auth  required  /lib/security/\$ISA/pam_wheel.so use_uid)"                   >> $CREATE_FILE 2>&1
echo "root 계정 su 제한 TIP"												>> $CREATE_FILE 2>&1
echo "su를 제한하기위해서는 다음조건이 충족되어야한다."                           >> $CREATE_FILE 2>&1
echo "기본적으로 리눅스운영체제에는  /etc/pam.d/su 파일에 pam_wheel.so"    >> $CREATE_FILE 2>&1
echo "설정값이 주석처리되어있음 이부분을 주석해재 한후 wheel 그룹에 su를"  >> $CREATE_FILE 2>&1
echo "사용할 user를 등록하면 wheel 그룹에 등록된 사용자만 su 명령을 사용할수 있게됨"  >> $CREATE_FILE 2>&1
echo "룰이 정상적으로 적용되면 비인가자가 su 를 사용하여 정상적인 패스워드를 입력해도 패스워드가 틀렸다는 메세지 가 출력되므로"  >> $CREATE_FILE 2>&1
echo "사용자 본인은 패스워드가 틀린지 알게된다."  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/pam.d/su 파일 설정"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

cat /etc/pam.d/su                                                                                 >> $CREATE_FILE 2>&1

echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_45_flag=0
if [ -f /etc/pam.d/su ]
then
	pam_wheel_check=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep -v '^#' | grep -v "^$" `
	if [ `echo $pam_wheel_check | wc -w` -eq 0 ] # wc -w 는 유니코드로 이루어진 단어의 개수
	then

		echo "pam_wheel.so 설정 내용이 주석이거나 설정되어 있지 않습니다. (su 권한 확인 필요)"                                                  >> $CREATE_FILE 2>&1
		u_45_flag=1 # BAD
	else
		echo $pam_wheel_check                               								   >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/pam.d/su 파일을 찾을 수 없습니다."                                                >> $CREATE_FILE 2>&1
	u_45_flag=3 # M/T
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② su 파일권한"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f /bin/su ]
then
	ls -alL /bin/su                                                                           >> $CREATE_FILE 2>&1
	sugroup=`ls -alL /bin/su`

elif [ -f /usr/bin/su ]
then
	ls -alL /usr/bin/su                                                                           >> $CREATE_FILE 2>&1
	sugroup=`ls -alL /usr/bin/su`	

elif [ `which su 2>/dev/null | wc -l` -ne 0 ]
	then
	sucommand=`which su`;
	ls -alL $sucommand                                                                           >> $CREATE_FILE 2>&1
	sugroup=`ls -alL $sucommand`

fi

if [ `echo $sugroup | wc -l` -ne 0 ]
then

	if [ `echo $sugroup | awk -F" " '{print $1}' | grep '.....-.---' | wc -l` -eq 0 -o `echo $sugroup | awk -F" " '{ print $3 }'` != "root" ]
	then
		echo "Permission not satisfied"                                                 >> $CREATE_FILE 2>&1
		u_45_flag=1 # BAD
	else
		echo "su 권한 양호"                                                 >> $CREATE_FILE 2>&1
		u_45_flag=2 # GOOD
	fi 
else [ `which su | grep -v 'no ' | wc -l` -eq 0 ]

	echo "su 명령 파일을 찾을 수 없습니다."                                                      >> $CREATE_FILE 2>&1
	# u_45_flag=3 # M/T
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ su 명령그룹"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep -v '^#' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}' | wc -l` -gt 0 ]
	then
		pamsugroup=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep -v '^#' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}'`
		echo "/etc/pam.d/su 파일 내 - su명령 그룹(PAM모듈): `egrep "^$pamsugroup" /etc/group`"                         >> $CREATE_FILE 2>&1
	fi
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | egrep -v 'trust|#' | wc -l` -gt 0 ]
	then
		echo "/etc/group 내 - su명령 그룹(PAM모듈)"."`cat /etc/group | grep '^wheel:'`"                              >> $CREATE_FILE 2>&1
	
	fi

fi
# echo "- su명령 그룹(명령파일): `egrep "^$sugroup" /etc/group`"                               >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo [결과] ${FLAG_TABLE[$u_45_flag]}          	                                                                 >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-45 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_46() {
echo "[U-46 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.7 패스워드 최소 길이 설정 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.7 패스워드 최소 길이 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호"                          >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MIN_LEN 8 이상이면 양호)"                                                >> $CREATE_FILE 2>&1 
echo "PAM 0.1 에서 pam_cracklib 이 적용되기 때문에 password requistie pam_pwquality.so 설정을 먼저 확인해야한다"                                                >> $CREATE_FILE 2>&1 
echo "비밀번호 길이 설정 파일 우선 순위"                                               >> $CREATE_FILE 2>&1 
echo "1. /etc/pam.d/system-auth"                                               >> $CREATE_FILE 2>&1 
echo "password requisite pam_pwquality.so minlen=8"                            >> $CREATE_FILE 2>&1 
echo "2. /etc/security/pwquailty.conf"                                               >> $CREATE_FILE 2>&1 
echo "minlen=8"                                                                                  >> $CREATE_FILE 2>&1 
echo "3. /etc/login.defs (pam.d 기능 설정 시 우선순위에서 밀림)"                                                               >> $CREATE_FILE 2>&1 
echo "       : (PASS_MIN_LEN 8 이상이면 양호)"                                                >> $CREATE_FILE 2>&1 
echo "4. solaris 기준 - /etc/default/passwd"                                                                >> $CREATE_FILE 2>&1 
echo "       : (PASS_MIN_LEN 8 이상이면 양호)"                                                >> $CREATE_FILE 2>&1 
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

u_46_flag=0

if [ ! $os_version -eq 1 ] # not solaris
	then
	if [ -f /etc/login.defs ] # 
	then
		echo "[login.defs 설정]"                                                              >> $CREATE_FILE 2>&1
		
		grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"                                      >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1	
		if [ `cat /etc/login.defs | grep "PASS_MIN_LEN" | grep -v "#" | wc -l` -eq 0 ]
		then
			let u_46_flag=$u_46_flag+1
			echo "설정이 되어 있지 않습니다 . (취약)"          	                                                                 >> $CREATE_FILE 2>&1
	    	echo " "                                                                                       >> $CREATE_FILE 2>&1
	    else
		    if [ `cat /etc/login.defs | grep -v "#" | grep "PASS_MIN_LEN" | awk -F" " '{ print $2 }'` -le 7 ] 
		    then
		    	let u_46_flag=$u_46_flag+1
		    	echo "최소 비밀번호 길이를 확인하십시오. (취약)"          	                                                                 >> $CREATE_FILE 2>&1
		    	echo " "                                                                                       >> $CREATE_FILE 2>&1
		    fi  
		fi
	else
		echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	fi

	if [ `cat /etc/pam.d/system-auth 2> /dev/null | grep -i "minlen" | grep -v "#" | wc -w` -ne 0 ]; # 
	then
		echo "[pam system-auth 설정]"                                                              >> $CREATE_FILE 2>&1
		
		grep -v '^ *#' /etc/pam.d/system-auth | grep -i "minlen"                                      >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1	
		
	    if [ `cat /etc/pam.d/system-auth | grep -i "minlen" | grep -v "#" | awk -F" " '{ print $2 }'` -le 7 ] 
	    then
	    	let u_46_flag=$u_46_flag+1
	    	echo "최소 비밀번호 길이를 확인하십시오. (취약)"          	                                                                 >> $CREATE_FILE 2>&1
	    	echo " "                                                                                       >> $CREATE_FILE 2>&1
	    fi  
		
	fi 

	if [ `cat /etc/security/pwquality.conf 2>/dev/null | grep -i "minlen" | grep -v "#" | wc -w` -ne 0 ]; # 
	then
		echo "[pam pwquality 설정]"                                                              >> $CREATE_FILE 2>&1
		
		grep -v '^ *#' /etc/security/pwquality.conf | grep -i "minlen"                                      >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1	

		
	    if [ `cat /etc/security/pwquality.conf | grep -i "minlen" | grep -v "#" | awk -F"=" '{ print $2 }' | xargs` -le 7 ] 
	    then
	    	let u_46_flag=$u_46_flag+1
	    	echo "최소 비밀번호 길이를 확인하십시오. (취약)"          	                                                                 >> $CREATE_FILE 2>&1
	    	echo " "                                                                                       >> $CREATE_FILE 2>&1
	    fi  	
	fi

else # solaris

    if [ -f /etc/default/passwd ]
      then
      
        grep -v '^ *#' /etc/default/passwd | grep -i "PASSLENGTH"                                               >> $CREATE_FILE 2>&1
        
      else
        echo "/etc/default/passwd 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    if [ `cat /etc/default/passwd | grep -i "PASSLENGTH" | grep -v "^ *#" | egrep [0-9] | awk -F= '{print $2}'| wc -l` -eq 0 ]
      then
      	let u_46_flag=0
        echo "PASSLENGTH 가 주석인 경우 8자리가 기준입니다"                           >> $CREATE_FILE 2>&1
      else
        if [ `cat /etc/default/passwd | grep -i "PASSLENGTH" | grep -v "^ *#" | awk -F= '{print $2}'` -ge 8 ]
          then
            let u_46_flag=0
          else
            let u_46_flag=$u_46_flag+1                                                                         >> $CREATE_FILE 2>&1
        fi
    fi


fi
if [ $u_46_flag -gt 5 ]
then	
	echo [결과] M          	                                                                 >> $CREATE_FILE 2>&1

elif [ $u_46_flag -gt 0 ]
then
	echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1
else
	echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-46 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_47() {
echo "[U-47 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.8 패스워드 최대 사용 기간 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.8 패스워드 최대 사용 기간 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최대 사용기간이 90일 이하로 설정되어 있으면 양호"                       >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MAX_DAYS 90 이하이면 양호)"                                              >> $CREATE_FILE 2>&1 
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_47_flag=0

if [ ! $os_version -eq 1 ] # not solaris
then
	if [ -f /etc/login.defs ]
	then
		grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS"                                      >> $CREATE_FILE 2>&1
		if [ `cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep -v "#" | wc -l` -eq 0 ]
		then
			let u_47_flag=$u_47_flag+1
			echo "설정이 되어 있지 않습니다 . (취약)"          	                                                                 >> $CREATE_FILE 2>&1
	    	echo " "                                                                                       >> $CREATE_FILE 2>&1	
	    else
		    if [ `cat /etc/login.defs | grep -v  "#" | grep "PASS_MAX_DAYS" | awk -F" " '{ print $2 }'` -gt 90 ] 
		    then
		    	let u_47_flag=$u_47_flag+1
		    	
		    	echo "최대 기한 설정을 확인하십시오. (취약)"          	                                                                 >> $CREATE_FILE 2>&1
		    	echo " "                                                                                       >> $CREATE_FILE 2>&1
		    fi
		fi
	else
		echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	fi

else # solaris

    if [ -f /etc/default/passwd ]
      then
        grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS"                                                 >> $CREATE_FILE 2>&1
      else
        echo "/etc/default/passwd 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1


    if [ `cat /etc/default/passwd | grep -i "MAXWEEKS" | grep -v "^ *#" | egrep  [0-9]| awk -F= '{print $2}'| wc -l ` -eq 0 ]
      then
        let u_47_flag=$u_47_flag+1
      else
        if [ `cat /etc/default/passwd | grep -i "MAXWEEKS" | grep -v "^ *#" | awk -F= '{print $2}'` -le 12 ]
          then
            let u_47_flag=0
          else
            let u_47_flag=$u_47_flag+1
        fi
    fi


fi
if [ $u_47_flag -gt 0 ]
then
	echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1
else
	echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-47 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_48(){

echo "[U-48 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.9 패스워드 최소 사용 기간 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.9 패스워드 최소 사용 기간 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 사용기간이 1일로 설정되어 있으면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (PASS_MIN_DAYS 1 이상이면 양호)"                                               >> $CREATE_FILE 2>&1 
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_48_flag=0

if [ ! $os_version -eq 1 ] # not solaris
then
	if [ -f /etc/login.defs ]
	then
		grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS"                                      >> $CREATE_FILE 2>&1
		if [ `cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep -v "#" | wc -l` -eq 0 ]
		then
			let u_48_flag=$u_48_flag+1
			echo "설정이 되어 있지 않습니다 . (취약)"          	                                                                 >> $CREATE_FILE 2>&1
	    	echo " "                                                                                       >> $CREATE_FILE 2>&1	
	    else
		    if [ `cat /etc/login.defs | grep -v  "#"| grep "PASS_MIN_DAYS" | awk -F" " '{ print $2 }'` -lt 1 ] 
		    then
		    	let u_48_flag=$u_48_flag+1
		    	echo "최소 기한 설정을 확인하십시오. (취약)"          	                                                                 >> $CREATE_FILE 2>&1
		    	echo " "                                                                                       >> $CREATE_FILE 2>&1
		    fi
		fi
	else
		echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	fi

	if [ $u_48_flag -gt 5 ]
	then	
		echo [결과] M          	                                                                 >> $CREATE_FILE 2>&1

	elif [ $u_48_flag -gt 0 ]
	then
		echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1
	else
		echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
	fi

else #  solaris


    if [ -f /etc/default/passwd ]
      then
        grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS"                                                 >> $CREATE_FILE 2>&1
      else
        echo "/etc/default/passwd 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    if [ `cat /etc/default/passwd | grep -i "MINWEEKS" | egrep [0-9] | grep -v "^ *#" | awk -F= '{print $2}'| wc -l` -eq 0 ]
      then
        let u_48_flag=$u_48_flag+1
      else
        if [ `cat /etc/default/passwd | grep -i "MINWEEKS" |  grep -v "^ *#" | awk -F= '{print $2}'` -ge 1 ]
          then
            let u_48_flag=0
          else
            let u_48_flag=$u_48_flag+1
        fi
    fi

	if [ $u_48_flag -gt 0 ]
	then
		echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1
	else
		echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
	fi    

fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-48 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}



U_49() {
echo "[U-49 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.10 불필요한 계정 제거 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.10 불필요한 계정 제거               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일에 Default 계정 점검(ex: adm, lp, sync, shutdown, halt, news, uucp, operator, games, gopher, nfsnobody, squid)"             >> $CREATE_FILE 2>&1
echo "				로그인 실패 기록 점검을 통한 미사용 계정 및 의심스러운 계정 확인"			>> $CREATE_FILE 2>&1
echo "불필요한 계정 제거 TIP"												>> $CREATE_FILE 2>&1
echo "리눅스에는 최초 OS설치당시부터 존재하는 계정들은 시스템계정들이므로"        >> $CREATE_FILE 2>&1
echo "쉘이 부여되어있지 않다."     												>> $CREATE_FILE 2>&1
echo "원격접속이 가능한 쉘이 부여된 계정 (UID500이상)을 중점적으로 확인한다."   >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_49_flag=0
u_49_flag_never=0

if [ ! $os_version -eq 1 ] # not solaris
then
	if [ -f /etc/login.defs ]
	then
		grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS (참고용)"                                     >> $CREATE_FILE 2>&1
	else
		echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "■ REPORT 2"                                                                                 >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	if [ `cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | wc -l` -eq 0 ]
	then
	  echo "☞ lp, uucp, nuucp 계정이 존재하지 않습니다."                                          >> $CREATE_FILE 2>&1
	else
	  cat /etc/passwd | egrep "^lp|^uucp|^nuucp"                                                   >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1

	echo "☞ Default 계정 점검" >> $CREATE_FILE 2>&1
	echo "cat /etc/passwd | egrep \"adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid\"" >> $CREATE_FILE 2>&1
	cat /etc/passwd | egrep "adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "☞ 접속 로그 확인" >> $CREATE_FILE 2>&1
	echo "#cat /var/log/loginlog" >> $CREATE_FILE 2>&1
	cat /var/log/loginlog >> $CREATE_FILE 2>&1
	echo "." >> $CREATE_FILE 2>&1
	echo "☞ su 로그 확인" >> $CREATE_FILE 2>&1
	echo "#cat /var/log/sulog" >> $CREATE_FILE 2>&1
	cat /var/log/sulog >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ [휴면계정확인]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	lastlog | grep Never >> $CREATE_FILE 2>&1
	echo "☞ [휴면계정을 제외한 계정 확인]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	lastlog | grep -v Never >> $CREATE_FILE 2>&1
	if [ `lastlog | grep Never | wc -l` -ne 0 ]
	then
		u_49_flag_never=1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ [90일 이전 로그인 계정 확인]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	test_5=`lastlog -t 90 | grep -v Never | grep -v Username | awk -F" " '{print $1}'`

	for t2 in `lastlog | grep -v Never | grep -v Username | awk -F" " '{print $1}'`
	do
		
		if [ `echo $test_5 | grep $t2 | grep -v "^ *$" | wc -l` -eq 0 ]
		then
			lastlog -u $t2 | grep -v "^Username" >> $CREATE_FILE 2>&1
			let u_49_flag=$u_49_flag+1
		fi
	done

	echo " " >> $CREATE_FILE 2>&1
	echo "☞ 로그인 실패 기록 점검" >> $CREATE_FILE 2>&1
	echo "#cat /var/log/secure | grep "failed"" >> $CREATE_FILE 2>&1
	cat /var/log/secure 2>/dev/null | grep "failed" | sort >> $CREATE_FILE 2>&1
	echo " "
                                                                                     >> $CREATE_FILE 2>&1                   

else # solaris

    echo "① 기본 시스템 계정(adm, lp, sync, shutdown, halt, news, uucp, nuucp, operator, games, gopher, nfsnobody, squid) " >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    if [ `cat /etc/passwd | egrep "^adm:|^lp:| ^sync: | ^shutdown:| ^halt:|^news:|^uucp:|^nuucp:|^operator:|^games:|^gopher:|^nfsnobody:|^squid:" | wc -l` -eq 0 ]
      then
        echo "기본 계정이 존재하지 않습니다"                                                                 >> $CREATE_FILE 2>&1
      else
        #20180116-03 : 아래 문장 추가
        echo "불필요한 계정은 아래와 같습니다."                                                                 >> $CREATE_FILE 2>&1
        cat /etc/passwd | egrep "^adm:|^lp:| ^sync: | ^shutdown:| ^halt:|^news:|^uucp:|^nuucp:|^operator:|^games:|^gopher:|^nfsnobody:|^squid:" >> $CREATE_FILE 2>&1
        
    fi
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    echo "② 사용자 계정 정보(참고)"                                                                            >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    cat /etc/passwd                                                                                             >> $CREATE_FILE 2>&1


fi
let u_49_flag=3

echo " "                                                                                                    >> $CREATE_FILE 2>&1
echo [결과] ${FLAG_TABLE[$u_49_flag]}				                                                                   >> $CREATE_FILE 2>&1


echo "[U-49 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1                   

}

U_50() {
echo "[U-50 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.11 관리자 그룹에 최소한의 계정 포함 ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       1.11 관리자 그룹에 최소한의 계정 포함        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① 관리자 계정"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

u_50_flag=2
if [ ! $os_version -eq 1 ] # not solaris
then
	if [ -f /etc/passwd ]
	  then
	    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                     >> $CREATE_FILE 2>&1
	  else
	    echo "/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
	    u_50_flag=3
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② 관리자 계정이 포함된 그룹 확인"                                                       >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	for group in `awk -F: '$3==0 { print $1 }' /etc/passwd`
	do
		cat /etc/group | grep "$group"                                                               >> $CREATE_FILE 2>&1
		if [ `cat /etc/group | awk -F":" 'index($1,"$group")' | awk -F ":" '{ print $4 }' | grep -v "^ *$" | wc -l` -gt 0 ]
		then
			u_50_flag=3
		fi
	done
else  # solaris
    if [ -f /etc/group ]
      then
        echo "[관리자 그룹 계정 현황]"                                                                          >> $CREATE_FILE 2>&1
        cat /etc/group | grep "root:"                                                                           >> $CREATE_FILE 2>&1
      else
        echo " /etc/group 파일이 없습니다."                                                                     >> $CREATE_FILE 2>&1
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    if [ `cat /etc/group | grep "root:" | awk -F':' '{print $4}' | sed '/^$/d' | wc -l` -eq 0 ]
      then
      	let u_50_flag=2
      else
        let u_50_flag=1
    fi
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo [결과] ${FLAG_TABLE[$u_50_flag]}                                                                            >> $CREATE_FILE 2>&1
echo "[U-50 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1                   
}


U_51() {
echo "[U-51 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.12 계정이 존재하지 않는 GID 금지 #################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        1.12 계정이 존재하지 않는 GID 금지         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 구성원이 존재하지 않는 빈 그룹이 발견되지 않을 경우 양호"                        >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 구성원이 존재하지 않는 그룹"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	for gid in `awk -F: '$4==null {print $3}' /etc/group`
	do
		if [ `grep -c $gid /etc/passwd` -eq 0 ]
		then
			grep $gid /etc/group                                                                     >> nullgid.txt
		fi		
	done

if [ `cat nullgid.txt 2>/dev/null | wc -l` -eq 0 ]
then
		echo "구성원이 존재하지 않는 그룹이 발견되지 않았습니다."                                  >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		echo [결과] Y 	                                                                           >> $CREATE_FILE 2>&1
else
		cat nullgid.txt                                                                            >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		echo "구성원이 존재하지 않는 그룹 개수 : " `cat nullgid.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`                >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		echo [결과] M                    >> $CREATE_FILE 2>&1
fi
rm -rf nullgid.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-51 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                      >> $CREATE_FILE 2>&1
}

U_52() {
echo "[U-52 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.13 동일한 UID 금지 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.13 동일한 UID 금지                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"                              >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 동일한 UID를 사용하는 계정 "                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       > total-equaluid.txt
u_52_flag=0
for uid in `cat /etc/passwd | awk -F: '{print $3}'`
do
	cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }' 2>/dev/null >/dev/null                   > equaluid.txt
	if [ `cat equaluid.txt | wc -l` -gt 1 ]
	then
		cat equaluid.txt                                                                           >> total-equaluid.txt
	fi
done
if [ `sort -k 1 total-equaluid.txt | wc -l` -gt 1 ]
then
	sort -k 1 total-equaluid.txt | uniq -d                                                       >> $CREATE_FILE 2>&1
	u_52_flag=1 # BAD
else
	echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다."                                     >> $CREATE_FILE 2>&1
	u_52_flag=2 # GOOD
fi
echo " "	                                                                                     >> $CREATE_FILE 2>&1

if [ $u_52_flag == 1 ] 
then
	echo [결과] N                                                                            >> $CREATE_FILE 2>&1
elif [ $u_52_flag == 2 ]
then
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1 
else
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1 
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-52 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf equaluid.txt
rm -rf total-equaluid.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


}


U_53() {
echo "[U-53 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.14 사용자 Shell 점검 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.14 사용자 Shell 점검               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 쉘이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "사용자 Shell 점검 TIP"												>> $CREATE_FILE 2>&1
echo "리눅스에서 아무쉘도 부여하지 않아도 계정으로 접속이 가능하므로  /bin/false ,  /no shell , bin/nologin   설정이 필요함"    >> $CREATE_FILE 2>&1
echo "예1] news:x:9:13:news:/etc/news: [패스워드 설정시 접속이가능함]"                                               >> $CREATE_FILE 2>&1
echo "예2] news:x:9:13:news:/etc/news:/sbin/nologin [패스워드 설정해도 접속이불가능함]"                                 >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 로그인이 필요하지 않은 시스템 계정 확인"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f /etc/passwd ]
then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "/var/adm" | grep -v "admin" > tmp_53.txt
    cat tmp_53.txt																																						 >> $CREATE_FILE 2>&1
    echo " "                                                                                    >> $CREATE_FILE 2>&1
  	u_53_num_flag=`egrep -v "false|nologin" tmp_53.txt| wc -l` 
   	echo "확인해야할 쉘 개수 : "$u_53_num_flag                                                >> $CREATE_FILE 2>&1
 
    if [ $u_53_num_flag -gt 0 ]
    then

		echo [결과] N                                                                              >> $CREATE_FILE 2>&1

    else
    	echo [결과] Y                                                                              >> $CREATE_FILE 2>&1
    fi
else
    echo "/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
    echo " "                                                                                       >> $CREATE_FILE 2>&1
    echo [결과] M                                                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-53 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
rm -f tmp_53.txt
}

U_54() {
echo "[U-54 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.15 Session Timeout 설정 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.15 Session Timeout 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/profile 에서 TMOUT=600 또는 /etc/csh.login 에서 autologout=5 로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_54_bash_flag=0
U_54_csh_flag=0
U_54_flag_is_good=0
echo "☞ 현재 사용 쉘 "                                                               >> $CREATE_FILE 2>&1

echo $SHELL                                                               >> $CREATE_FILE 2>&1
echo ""                                                               >> $CREATE_FILE 2>&1

if [ `echo $SHELL | egrep "/bin/csh|/bin/tcsh" | wc -l` -eq 1 ]
then
	U_54_csh_flag=1
elif [ `echo $SHELL | egrep "/bin/bash|/bin/sh|/bin/ksh" | wc -l` -eq 1 ]
then	
	
	U_54_bash_flag=1
else 
	
	U_54_flag_is_good=3  # M/T 
fi


echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
echo "☞ 현재 로그인 계정 TMOUT"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1

if [ `set | egrep -i "TMOUT|autologout" | wc -l` -gt 0 ]
	then
		if [ ! -z $TMOUT ]
		then
			echo "TMOUT"                                                 >> $CREATE_FILE 2>&1
			echo $TMOUT                                                 >> $CREATE_FILE 2>&1

		fi
		if [ ! -z $autologout ]
		then
			echo "autologout"                                                 >> $CREATE_FILE 2>&1
			echo $autologout                                                 >> $CREATE_FILE 2>&1
		fi
	else
		echo "TMOUT 이 설정되어 있지 않습니다."                                                      >> $CREATE_FILE 2>&1
		u_53_flag=1 # BAD
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ TMOUT 설정 확인"                                                                      >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/profile 파일"                                                                    >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
if [ $U_54_bash_flag == 1 ] # bash shell
then
	if [ -f /etc/profile ]
	then
	  if [ `cat /etc/profile | grep -i "TMOUT=" | grep -v "^#" | wc -l` -gt 0 ]
	  then
	  	tmout=`cat /etc/profile | grep -i "TMOUT=" | grep -v "^#"`

	  	echo $tmout                                            >> $CREATE_FILE 2>&1
	  	echo ""                                                    >> $CREATE_FILE 2>&1
	  	tmvalue=`cat /etc/profile | grep -v "^ *#" | grep 'TMOUT=' | tail -1 | awk -F"=" '{print $2}'`
	  	
	  	if [ $tmvalue -le 600 -a $tmvalue != 0 ]
	  	then
	  		U_54_flag_is_good=2 # GOOD
	  	else
	  		echo "TMOUT 설정 변경이 필요합니다. (취약)"                                                    >> $CREATE_FILE 2>&1

	  		U_54_flag_is_good=1 # BAD
	  	fi
	  else
	  	echo "TMOUT 이 설정되어 있지 않습니다."                                                    >> $CREATE_FILE 2>&1
	  	U_54_flag_is_good=1 #BAD
	  fi
	else
	  echo "/etc/profile 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
	  u_53_flag=3 # M/T
	fi
	# solaris
	if [ ! -f /etc/profile ] && [ -f /etc/default/login ];
	then
	  if [ `cat /etc/default/login | grep -i "TIMEOUT=" | grep -v "^#" | wc -l` -gt 0 ]
	  then
	  	tmout=`cat /etc/default/login | grep -i "TIMEOUT=" | grep -v "^#"`
	  	echo $tmout                                            >> $CREATE_FILE 2>&1
	  	echo ""                                                    >> $CREATE_FILE 2>&1
	  	tmvalue=`cat /etc/default/login | grep -v "^ *#" | grep 'TIMEOUT=' | tail -1 | awk -F"=" '{print $2}'`
	  	if [ $tmvalue -le 600 -a $tmvalue != 0 ]
	  	then
	  		U_54_flag_is_good=2 # GOOD
	  	else
	  		echo "TIMEOUT 설정 변경이 필요합니다. (취약)"                                                    >> $CREATE_FILE 2>&1

	  		U_54_flag_is_good=1 # BAD
	  	fi
	  else
	  	echo "TIMEOUT 이 설정되어 있지 않습니다."                                                    >> $CREATE_FILE 2>&1
	  	U_54_flag_is_good=1 #BAD
	  fi
	else
	  echo "/etc/default/login 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
	  u_53_flag=3 # M/T
	fi

elif [ $U_54_csh_flag == 1 ] # c shell used
then
	u_53_tmp_flag=0
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② /etc/csh.login 파일"                                                                  >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
	if [ -f /etc/csh.login ]
	then
	  if [ `cat /etc/csh.login | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
	  then
	  	cat /etc/csh.login | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
	  	tmout=`cat /etc/csh.login | grep -i autologout | grep -v "^#"`
	  	echo $tmout                                            >> $CREATE_FILE 2>&1
	  	echo ""                                                    >> $CREATE_FILE 2>&1
	  	if [ `echo $tmout | sed -n 's/TMOUT=\([0-9]\)/\1/p'` -le 10 -a `echo $tmout` != "autologout=0" ]
	  	then
	  		U_54_flag_is_good=2 # GOOD
	  	else
	  		U_54_flag_is_good=1 # BAD
	  		echo "autologout 설정 변경이 필요합니다. (취약)"                                                    >> $CREATE_FILE 2>&1
	  	fi

	  	
	  else
	  	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
	  	let u_53_tmp_flag=$u_53_tmp_flag+1 #BAD
	  fi
	else
	  echo "/etc/csh.login 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
	  u_53_flag=3 # M/T
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ /etc/csh.cshrc 파일"                                                                  >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
	if [ -f /etc/csh.cshrc ]

	then
	  if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
	  then
	  	cat /etc/csh.cshrc | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
	  	tmout=`cat /etc/csh.login | grep -i autologout | grep -v "^#"`

	  	echo $tmout                                            >> $CREATE_FILE 2>&1
	  	echo ""                                                    >> $CREATE_FILE 2>&1
	  	if [ `echo $tmout | sed -n 's/TMOUT=\([0-9]\)/\1/p'` -le 10 -a `echo $tmout` != "autologout=0" ]
	  	then
	  		U_54_flag_is_good=2 # GOOD
	  	else
	  		U_54_flag_is_good=1 # BAD
	  		echo "autologout 설정 변경이 필요합니다. (취약)"                                                    >> $CREATE_FILE 2>&1
	  	fi

	  else
	  	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
	  	let u_53_tmp_flag=$u_53_tmp_flag+1 #BAD
	  fi
	else
	  echo "/etc/csh.cshrc 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
	  u_53_flag=3 # M/T
	fi
	if [ $u_53_tmp_flag == 2 ] #csh.login , csh.cshrc 둘다 autologout 설정이 없는 경우
	then
		echo "autologout 이 두 파일 모두 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
		U_54_flag_is_good=1
	fi 
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $U_54_flag_is_good == 1 ]
then
	echo [결과] N                                                                            >> $CREATE_FILE 2>&1
elif [ $U_54_flag_is_good == 2 ]
then
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
else 
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1

fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-54 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_05() {
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#########################    2. 파일 및 디렉토리 관리    ##############################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "[U-5 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 #######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   2.1 root 홈, 패스 디렉터리 권한 및 패스 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Path 설정에 “.” 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"                >> $CREATE_FILE 2>&1
echo "root 홈, 패스 디렉터리 권한 및 패스 설정 설정 TIP"												>> $CREATE_FILE 2>&1
echo "PATH 경로설정중 “.”이 맨 앞 또는 중간에 선언되어 있을 경우 관리자가 실제 의도한 경로의 정상적인 파일이 아닌 공격자가"   >> $CREATE_FILE 2>&1
echo "생성한 파일을 실행할 수 있는 위험이 있다.“.”의 위치를 맨 뒤로 설정되어있지 않을경우 취약함"  >> $CREATE_FILE 2>&1
echo "현재 디렉토리를 지칭하는 “.”는 PATH 내의 맨 뒤에 위치하도록 설정되어있어야함"               >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ PATH 설정 확인"                                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo $PATH                                                                                     >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
let PATH_SIZE=${#PATH}-1

#if [[ $test =~ :: ]] || [[ `echo ${test:0:$PATH_SIZE}` =~ "." ]] # UBUNTU
if [ `echo ${PATH:0:$PATH_SIZE} | egrep "::|\." | wc -l` -ne 0 ]
then
	echo [결과] N                                                                            >> $CREATE_FILE 2>&1
else
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
fi

echo "[U-5 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}


U_06() {
echo "[U-6 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.2 파일 및 디렉터리 소유자 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.2 파일 및 디렉터리 소유자 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 지,"   >> $CREATE_FILE 2>&1
echo "조치 방법 : 소유자가 존재하지 않는 파일 및 디렉터리 삭제 또는, 소유자 변경"    >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 사용자 홈 디렉터리"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

# /home /tmp /opt /etc/
ServiceDIR="/etc /tmp /opt /home /export/home"
no_user_count=0
echo "-------no_user_file---------" >> $CREATE_FILE 2>&1

for TARGETDIR in $ServiceDIR
	do
	NO_USER_LIST=`find $TARGETDIR \( -nouser -o -nogroup \) 2>/dev/null` 
	no_user_count=$(($no_user_count+`echo $NO_USER_LIST | wc -w`))

		for noUSER in $NO_USER_LIST
		do 
			echo $noUSER                                                                                       >> $CREATE_FILE 2>&1
		done
done

if [ $no_user_count -lt 1 ]
	then

		echo "파일 없음"                                                                                       >> $CREATE_FILE 2>&1
		echo " "                                                                                         >> $CREATE_FILE 2>&1
		echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
		
else

	echo "no_user_file count : "$no_user_count                                                                                        >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1
fi 

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-6 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_07() {

echo "[U-7 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.3 /etc/passwd 파일 소유자 및 권한 설정 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.3 /etc/passwd 파일 소유자 및 권한 설정     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이하면 양호"                     >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_07_flag=0
if [ -f /etc/passwd ]
  then
    ls -alL /etc/passwd                                                                        >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
    ls -al /etc/passwd | awk -F" " '{print $3 ":" substr($1, 2, 3) }' > u_07.txt

    
    if [ `cat u_07.txt | awk -F":" '{ print $1 }'` == "root" ]
    then 
    	
    	u_07_flag=1

   	else
   
		echo "File owner not satisfied"                                                                    >> $CREATE_FILE 2>&1
		echo ""                                                                    >> $CREATE_FILE 2>&1
   		echo [결과] N                                                                    >> $CREATE_FILE 2>&1

   	fi

   	if [ $u_07_flag -eq 1 ] #second condition
   	then
   		
   		if [ `ls -al /etc/passwd | awk -F" " '{print $1}' | grep '...-..-..-' | wc -l` -ne 0 ]
   			then 
   				
	   			echo [결과] Y                                                                    >> $CREATE_FILE 2>&1
   			else
   				
   				echo "Permission not satisfied"                                                                    >> $CREATE_FILE 2>&1
   				echo ""                                                                    >> $CREATE_FILE 2>&1
	   			echo [결과] N                                                                    >> $CREATE_FILE 2>&1

   		fi
   	else
   		echo error
   	fi 
   	rm u_07.txt 2>/dev/null

   		
  else
    echo "☞ /etc/passwd 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
    echo [결과] M                                                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-7 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_08() {
echo "[U-8 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.4 /etc/shadow 파일 소유자 및 권한 설정 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.4 /etc/shadow 파일 소유자 및 권한 설정     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이면 양호"                     >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_08_flag=0
if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow                                                                          >> $CREATE_FILE 2>&1
	echo " "                                                                                   >> $CREATE_FILE 2>&1
	ls -al /etc/shadow | awk -F" " '{print $3 ":" substr($1, 2, 3) }' > u_08.txt
  	u_08_flag=0
    if [ `cat u_08.txt | awk -F":" '{ print $1 }'` == "root" ]
    then 
    	
    	u_08_flag=2

   	else
   		
		echo "File owner not satisfied"                                                                    >> $CREATE_FILE 2>&1
		echo ""                                                                    >> $CREATE_FILE 2>&1
   		echo [결과] N                                                                    >> $CREATE_FILE 2>&1


   	fi

   	if [ $u_08_flag == 2 ] #second condition
   	then
   		
   		if [ `ls -al /etc/shadow | awk -F" " '{print $1}' | grep '...-------' | wc -l` -ne 0 ] # 400 
   			then 
   				
	   			echo [결과] Y                                                                    >> $CREATE_FILE 2>&1
   			else
   				
   				echo "Permission not satisfied"                                                                    >> $CREATE_FILE 2>&1
   				echo ""                                                                    >> $CREATE_FILE 2>&1
	   			echo [결과] N                                                                    >> $CREATE_FILE 2>&1
   		fi
   	
   		
   	fi 
   	rm u_08.txt 2>/dev/null

else
	echo "☞ /etc/shadow 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
	echo " "                                                                                   >> $CREATE_FILE 2>&1
  echo [결과] M                                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-8 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}


U_09() {

echo "[U-9 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.5 /etc/hosts 파일 소유자 및 권한 설정 ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.5 /etc/hosts 파일 소유자 및 권한 설정      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 600 이면 양호"                      >> $CREATE_FILE 2>&1
echo "/etc/hosts 파일 소유자 및 권한 설정 TIP"											>> $CREATE_FILE 2>&1
echo "단 이항목을 조치하면 오라클 DB 접속이 불가한 경우 다수발생 특정 솔루션과 연동부분을 확인해야함(대안책 644)"    >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_09_flag=0
if [ -f /etc/hosts ]
  then
    ls -alL /etc/hosts                                                                         >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
    ls -al /etc/hosts | awk -F" " '{print $3 ":" substr($1, 2, 3) }' > u_09.txt

  	u_09_flag=0
    if [ `cat u_09.txt | awk -F":" '{ print $1 }'` == "root" ]
    then 
    	
    	u_09_flag=1

   	else
   		
		echo "File owner not satisfied"                                                                    >> $CREATE_FILE 2>&1
		echo ""                                                                    >> $CREATE_FILE 2>&1
   		echo [결과] N                                                                    >> $CREATE_FILE 2>&1


   	fi

   	if [ $u_09_flag == 1 ] #second condition
   	then
   		
   		if [ `ls -al /etc/hosts | awk -F" " '{print $1}' | grep "...-.--.--" | wc -l` -ne 0 ] # 2019 : 400, 2020 : 644
   			then 
   				
	   			echo [결과] Y                                                                    >> $CREATE_FILE 2>&1
   			else
   				
   				echo "Permission not satisfied"                                                                    >> $CREATE_FILE 2>&1
   				echo ""                                                                    >> $CREATE_FILE 2>&1
	   			echo [결과] N                                                                    >> $CREATE_FILE 2>&1
   		fi
   	
   	fi 
   	rm u_09.txt 2>/dev/null




   else
    echo "☞ /etc/hosts 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
    echo [결과] "Null:Null"                                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-9 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_10() {
echo "[U-10 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 ####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정  #################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/(x)inetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일의 소유자가 root 이고, 권한이 600 이면 양호" >> $CREATE_FILE 2>&1
echo "REDHAT 계열은 기본설치시 xinetd 가 미설치 되어있을수도 있음 /etc/xinetd.conf 가 존재하지 않는다면 미설치 확률 존재 "    >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/xinetd.conf 파일"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_10_is_null_flag=0
u_10_is_good_check=0	
u_10_is_xinetd_d_check=0
if [ -f /etc/xinetd.conf ]
then
	ls -alL /etc/xinetd.conf                                                                     >> $CREATE_FILE 2>&1
	
	if [ `ls -alL /etc/xinetd.conf | awk -F" " '{ print $1 }' | grep "...-------" | wc -l` -eq 0 -o `ls -alL /etc/xinetd.conf | awk -F" " '{print $3}'` != "root" ]
	then
		let u_10_is_good_check=$u_10_is_good_check+1
		echo ""							 >> $CREATE_FILE 2>&1
		echo "Permission Not satisfied" >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/xinetd.conf 파일은 없습니다."                                                     >> $CREATE_FILE 2>&1
	let u_10_is_null_flag="$u_10_is_null_flag"+1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/inetd.conf 파일"                                                                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
	then
		ls -alL /etc/inetd.conf                                                                     >> $CREATE_FILE 2>&1
		
		if [ `ls -alL /etc/inetd.conf | awk -F" " '{ print $1 }' | grep "...-------" | wc -l` -eq 0 -o `ls -alL /etc/inetd.conf | awk -F" " '{print $3}'` != "root" ]
			then

				let u_10_is_good_check="$u_10_is_good_check"+1
				echo ""							 >> $CREATE_FILE 2>&1
				echo "Permission Not satisfied" >> $CREATE_FILE 2>&1
		fi

	else
		echo "/etc/inetd.conf 파일은 없습니다."                                                     >> $CREATE_FILE 2>&1
		let u_10_is_null_flag="$u_10_is_null_flag"+1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/xinetd.d/ 파일"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
then
	ls -alL /etc/xinetd.d/*  2>/dev/null                                                                	   > tmp010.txt
	# cat tmp010.txt 																			>> $CREATE_FILE 2>&1
	echo " "																				 >> $CREATE_FILE 2>&1
	for file in `awk -F" " '{ print $9 }' tmp010.txt`
	do
		ls -alL $file >> $CREATE_FILE 2>&1
		if [ `ls -alL $file | awk -F" " '{ print $1 }' | grep "...-------" | wc -l` -eq 0 -o `ls -alL $file | awk -F" " '{ print $3 }'` != "root" ]
		then
			echo "Permission Not satisfied" >> $CREATE_FILE 2>&1
			let u_10_is_xinetd_d_check="$u_10_is_xinetd_d_check"+1
		fi	
	done

else 
	echo "/etc/xinetd.d가 없습니다"																				 >> $CREATE_FILE 2>&1
fi 

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $u_10_is_null_flag -eq 2 ]
	then
		echo [결과] Y                                                         >> $CREATE_FILE 2>&1

elif 
	[ $u_10_is_good_check -ne 0 -o $u_10_is_xinetd_d_check -ne 0 ]
	then
		echo [결과] N                                                         >> $CREATE_FILE 2>&1
else
		echo [결과] Y                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1    
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-10 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

rm -f tmp010.txt

}

U_11() {

echo "[U-11 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.7 /etc/syslog.conf 파일 소유자 및 권한 설정 ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.7 /etc/syslog.conf 파일 소유자 및 권한 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/syslog.conf 파일의 권한이 644 이면 양호"                                    >> $CREATE_FILE 2>&1
echo "경우에 따라 상위버전인 rsyslog.conf 를 사용할수도있음"                                      >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "SYSLOG File check "                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $os_version -eq 1 ]
then
	ps -waux | grep syslog | grep -v grep | grep -v dbus > u_11.txt
else
	ps -ef | grep syslog | grep -v grep | grep -v dbus > u_11.txt
fi
systype=`cat u_11.txt | awk -F" " '{ print $11}'`
if [ `echo $systype | grep "rsyslog" | wc -l` -gt 0 ] 
then
	echo "rsyslog 구동"                                                                   >> $CREATE_FILE 2>&1
	
elif [ `echo $systype | grep "syslog" | wc -l` -gt 0 ] 
then
	echo "syslog 구동"                                                                   >> $CREATE_FILE 2>&1
	
else
	echo "수동 체크 필요( $ ps -waux | grep syslog )"                                                                   >> $CREATE_FILE 2>&1
fi
cat u_11.txt                                                                   >> $CREATE_FILE 2>&1   
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ -f /etc/syslog.conf ]
then
    ls -alL /etc/syslog.conf                                                                   >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
    if [ ! `ls -alL /etc/syslog.conf | awk -F" " '{ print $1 }' | grep "...-------" | wc -l` -eq 0 -o `ls -alL /etc/syslog.conf | awk -F" " '{print $3}'` != "root" ]
    then
    	echo [결과] N                                                           	       >> $CREATE_FILE 2>&1
    else
    	echo [결과] Y                                                           	       >> $CREATE_FILE 2>&1
    fi

elif [ -f /etc/rsyslog.conf ]
then
	ls -alL /etc/rsyslog.conf                                                           	       >> $CREATE_FILE 2>&1
	echo " "                                                                          	         >> $CREATE_FILE 2>&1
    if [ ! `ls -alL /etc/rsyslog.conf | awk -F" " '{ print $1 }' | grep "...-------" | wc -l` -eq 0 -o `ls -alL /etc/rsyslog.conf | awk -F" " '{print $3}'` != "root" ]
    then
    	echo [결과] N                                                           	       >> $CREATE_FILE 2>&1
    else
    	echo [결과] Y                                                           	       >> $CREATE_FILE 2>&1
    fi
else
	echo [결과] M                                                           	       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-11 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
rm -rf u_11.txt

}

U_12() {
echo "[U-12 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.8 /etc/services 파일 소유자 및 권한 설정 #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.8 /etc/services 파일 소유자 및 권한 설정    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/services 파일의 권한이 644 이면 양호"                                       >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/services ]

  then
    ls -alL /etc/services                                                                      >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/services  | awk -F" " '{ print $1 }' | grep "\-..-.--.--" | wc -l` -eq 0 -o `ls -alL /etc/services | awk -F" " '{print $3}'` != "root" ]
    then
    	echo [결과] N                                                           	       >> $CREATE_FILE 2>&1
    else
    	echo [결과] Y                                                           	       >> $CREATE_FILE 2>&1
    fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-12 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_13() {
echo "[U-13 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.9 SUID,SGID,Stick bit 설정 파일 점검 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.9 SUID,SGID,Stick bit 설정 파일 점검      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"                               >> $CREATE_FILE 2>&1
echo "■ 조치방법: 불필요한 SUID, SGID 파일 제거"                               >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /usr -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \;     > U_13.txt
find /sbin -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \;    >> U_13.txt
u_13_flag=0
if [ -s U_13.txt ]
then
	linecount=`cat U_13.txt | wc -l`
	if [ $linecount -gt 100 ]
  then
  	echo "SUID,SGID,Sticky bit 설정 파일 (상위 100개)"                                          >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
	  head -100 U_13.txt                                                                          >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
  	echo " 등 총 "$linecount"개 파일 존재 (전체 목록은 스크립트 결과 파일 확인)"               >> $CREATE_FILE 2>&1
  	echo " "                                                                                   >> $CREATE_FILE 2>&1
		u_13_flag=3
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
  	echo "SUID,SGID,Sticky bit 설정 파일"                                                      >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
	  cat U_13.txt                                                                               >> $CREATE_FILE 2>&1
    echo " "                                                                                   >> $CREATE_FILE 2>&1
  	echo " 총 "$linecount"개 파일 존재"                                                        >> $CREATE_FILE 2>&1
  	echo " "                                                                                   >> $CREATE_FILE 2>&1
		u_13_flag=3
		echo " "                                                                                   >> $CREATE_FILE 2>&1
  fi
else
	echo "☞ SUID/SGID로 설정된 파일이 발견되지 않았습니다."                                     >> $CREATE_FILE 2>&1
	echo " " 		                                                                                 >> $CREATE_FILE 2>&1
	echo [결과] 0                                                   				            	       >> $CREATE_FILE 2>&1
fi

	if [ $os_version -eq 1 ] # solaris
	then
	    FILES="/usr/bin/admintool /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/lpset /usr/bin/newgrp 
	    /usr/bin/nispasswd /usr/bin/rdist /usr/bin/yppasswd /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo 
	    /usr/dt/bin/sdtcm_convert /usr/lib/fs/ufs/ufsdump /usr/lib/fs/ufs/ufsrestore /usr/lib/lp/bin/netpr 
	    /usr/openwin/bin/ff.core /usr/openwin/bin/kcms_calibrate /usr/openwin/bin/kcms_configure 
	    /usr/openwin/bin/xlock /usr/platform/sun4u/sbin/prtdiag /usr/sbin/arp /usr/sbin/lpmove 
	    /usr/sbin/prtconf /usr/sbin/sysdef /usr/sbin/sparcv7/prtconf /usr/sbin/sparcv7/sysdef 
	    /usr/sbin/sparcv9/prtconf /usr/sbin/sparcv9/sysdef"
	else # linux

	    FILES="/sbin/dump /sbin/restore /sbin/unix_hkpwd /usr/bin/cat /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd 
	    /usr/bin/lprm /usr/bin/lprm-lpd /usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute"
	fi 
    echo "권한 상승 공격을 할 수 있는 바이너리 중 존재하는 파일 리스트"   >> $CREATE_FILE 2>&1
    for check_file in $FILES
      do   
        if [ -f $check_file ]
          then
            if [ -g $check_file -o -u $check_file ]
              then
                echo `ls -alL $check_file`                                                                      >> $CREATE_FILE 2>&1
              else
                :
            fi
          
        fi
      done

    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    echo "setuid " > U_13_privilege_escalation_candidate.txt

    for check_file in $FILES
      do
        if [ -f $check_file ]
          then
            if [ `ls -alL $check_file |awk '{print $1}' | grep -i 's'| wc -l ` -gt 0 ]
              then
                ls -alL $check_file |awk '{print $1}' | grep -i 's'                         >> U_13_privilege_escalation_candidate.txt
              else
                echo " "                                                                    >> U_13_privilege_escalation_candidate.txt
            fi
        fi
      done

    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    if [ `cat U_13_privilege_escalation_candidate.txt | awk '{print $1}' | grep -i 's' | wc -l` -gt 1 ] 
      then
        let u_13_flag=1
      else 
        let u_13_flag=2
    fi

echo [결과] ${FLAG_TABLE[$u_13_flag]}                                            >> $CREATE_FILE 2>&1

rm -rf U_13_privilege_escalation_candidate.txt
rm -rf U_13.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-13 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_14() {
echo "[U-14 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #######"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "############ 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #############" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈디렉터리 환경변수 파일에 타사용자 쓰기 권한이 제거되어 있으면 양호"            >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 홈디렉터리 환경변수 파일"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .netrc .exrc .history .sh_history .bash_history .dtprofile"

u_14_bad_flag=0
for file in $FILES
do
  FILE=/$file

  if [ -f $FILE ]
  then
    ls -alL $FILE                                                                             >> $CREATE_FILE 2>&1
  fi
done
for dir in $HOMEDIRS
do
  for file in $FILES
  do
  	
    FILE=$dir/$file
    
    if [ -f $FILE ]
    then

    	ls -alL $FILE                                                                            >> $CREATE_FILE 2>&1
    	if [ `ls -alL $FILE | awk -F" " '{ print $1'} | grep "\-.......-." | wc -l` -eq 0 ] # 쓰기 권한이 없는 애를 만족한다면 
    		
    	then
      		u_14_bad_flag=1
      		echo "Permission not satisfied"                                                                             >> $CREATE_FILE 2>&1
      		echo "-------------------------"                                                                            >> $CREATE_FILE 2>&1
      	fi
      
    fi
  done
done
echo                                                                             >> $CREATE_FILE 2>&1

if [ $u_14_bad_flag != 1 ] 
then
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
else
	echo [결과] N                                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-14 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_15() {

echo "[U-15 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.11 world writable 파일 점검 ######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          2.11 world writable 파일 점검            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"            >> $CREATE_FILE 2>&1
echo "world writable 파일은 누구나 변경가능한 파일을 뜻함 [쓰기] 권한이  모든사용자게에 포함된파일"     >> $CREATE_FILE 2>&1
echo "단 파일의 타입이 link[lrwxrwxrwx] , soket[srwxrwxrwx] 파일은 제외한다[진단에 의미가없음 구조상 파일권한이 동일함]"         >> $CREATE_FILE 2>&1
echo "/proc|/lost+found|/system/contract/process/|/system/contract/device/|/sys/fs/cgroup/ 부분 제외"        >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_15_flag=0

find / -perm -2 -type d -ls  | grep -v drwxrwxrwt                           >> U_15_world_dir.txt 2>&1
find / -perm -2 -type f -ls  | egrep -v "/proc|/lost+found|/system/contract/process/|/system/contract/device/|/sys/fs/cgroup/" >> U_15_world_file.txt 2>&1

if [ -s U_15_world_dir.txt ]; then
      echo "▶ World Writable Directory 현황"                                                               >> $CREATE_FILE 2>&1
      cat U_15_world_dir.txt                                                                                    >> $CREATE_FILE 2>&1
      echo " "                                                                                              >> $CREATE_FILE 2>&1
fi
if [ -s U_15_world_file.txt ]; then
      echo "▶ World Writable File 현황"                                                                    >> $CREATE_FILE 2>&1
      cat U_15_world_file.txt                                                                                    >> $CREATE_FILE 2>&1
      echo " "                                                                                              >> $CREATE_FILE 2>&1
fi
if [ -s U_15_world_dir.txt ]; then
      let U_15_flag=1
else if [ -s U_15_world_file.txt ]; then
      let U_15_flag=1
  else
      echo "☞ World Writable 권한이 부여된 파일이 발견되지 않았습니다."                                    >> $CREATE_FILE 2>&1
      echo " "                                                                                              >> $CREATE_FILE 2>&1
      let U_15_flag=2
  fi
fi

echo " "                                                                                                    >> $CREATE_FILE 2>&1

rm -f U_15_world_dir.txt U_15_world_file.txt


echo [결과] ${FLAG_TABLE[$U_15_flag]}                                            >> $CREATE_FILE 2>&1
echo " "                                             >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-15 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_16() {
echo "[U-16 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.12 /dev에 존재하지 않는 device 파일 점검 #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.12 /dev에 존재하지 않는 device 파일 점검     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 : dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■        : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)"                  >> $CREATE_FILE 2>&1
echo "■        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)" >> $CREATE_FILE 2>&1
echo " /dev에 존재하지 않는 device 파일 점검 TIP"                  >> $CREATE_FILE 2>&1
echo  "Major Number는 많은 디바이스 드라이버 중에 하나를 구분하기 위해 쓰임"   >> $CREATE_FILE 2>&1
echo  "Minor Number는 디바이스 드라이버에서 특정한 디바이스를 가르킨다."					>> $CREATE_FILE 2>&1
echo  "왼쪽숫자는 Major Number 이며 우축숫자는 Minor Number 이다." 					>> $CREATE_FILE 2>&1
echo "예제] -rw-r--r-- 1 root root 80 Feb  9 20:24 /dev/.udev/db/block:loop1"           >> $CREATE_FILE 2>&1
echo "예제] 날짜 feb 월을 기준으로 왼쪽에 있는숫자가 Number 이며 하나만표시되면 Major Number 이다."    >> $CREATE_FILE 2>&1

echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /dev -type f -exec ls -l {} \;                                                            > u_16.txt

if [ -s u_16.txt ]
then
	cat u_16.txt                                                                                 >> $CREATE_FILE 2>&1
	echo '----------------------------------------------------------------'                       >> $CREATE_FILE 2>&1
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1
else
	echo "☞ dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다."                            >> $CREATE_FILE 2>&1
	echo " "                                                                            >> $CREATE_FILE 2>&1
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
fi
rm -rf u_16.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-16 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_17() {
echo "[U-17 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.13 HOME/.rhosts, hosts.equiv 사용 금지 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.13 HOME/.rhosts, hosts.equiv 사용 금지     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "■       : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인"          >> $CREATE_FILE 2>&1
echo "■       : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_17_flag=0
u_17_bad_flag=0
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep :$port | grep -i "^tcp"                                                  > u_17.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep :$port | grep -i "^tcp"                                                  >> u_17.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep :$port | grep -i "^tcp"                                                  >> u_17.txt
fi

if [ -s u_17.txt ]
then
	cat u_17.txt | grep -v '^ *$'                                                                >> $CREATE_FILE 2>&1
	u_17_flag=3
	

else
	echo "☞ r-command Service Disable"                                                          >> $CREATE_FILE 2>&1
	u_17_flag=2
fi
rm -rf u_17.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/hosts.equiv 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.equiv ]
	then
		echo "(1) Permission: "             						                            >> $CREATE_FILE 2>&1
		ls -al /etc/hosts.equiv             						                            >> $CREATE_FILE 2>&1
		if [ `ls -al /etc/hosts.equiv | awk -F" " '{ print $1}' | grep "...-------" | wc -l` -ne 0 ]
		then
			let u_17_bad_flag=$u_17_bad_flag+1
			echo "권한 값이 취약합니다. (취약)"                                                             >> $CREATE_FILE 2>&1
			echo " "                                                             >> $CREATE_FILE 2>&1
		fi
		echo "(2) 설정 내용:"                                                                      >> $CREATE_FILE 2>&1
		echo "----------------------------------------"                                            >> $CREATE_FILE 2>&1
		cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$'                                      >> $CREATE_FILE 2>&1
		if [ `cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$' | grep '\+' | wc -l` -gt 0 ]
		then
			
			let u_17_bad_flag=$u_17_bad_flag+1
			echo "결과 : + 설정 값이 존재합니다. (취약)"                                                             >> $CREATE_FILE 2>&1
			echo " "                                                             >> $CREATE_FILE 2>&1
		else
			echo "설정 내용이 없습니다."                                                             >> $CREATE_FILE 2>&1
		fi
	else
		echo "/etc/hosts.equiv 파일이 없습니다."                                                   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "④ 사용자 home directory .rhosts 설정 내용"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

for dir in $HOMEDIRS
do
	for file in $FILES
	do
		if [ -f $dir$file ]
		then
			echo " "                                                                                 > rhosts.txt
			echo "# $dir$file 파일 설정:"                                                            >> $CREATE_FILE 2>&1
			echo "(1) Permission: (`ls -al $dir$file`)"                                              >> $CREATE_FILE 2>&1
			echo $dir$file
			if [ `ls -al $dir$file | awk -F" " '{ print $1}' | grep "...-------" | wc -l` -ne 0 ]
			then
				let u_17_bad_flag=$u_17_bad_flag+1
				echo "권한 값이 취약합니다. (취약)"                                                             >> $CREATE_FILE 2>&1
				echo " "                                                             >> $CREATE_FILE 2>&1
			fi			
			echo "(2) 설정 내용:"                                                                    >> $CREATE_FILE 2>&1
			echo "----------------------------------------"                                          >> $CREATE_FILE 2>&1
			cat $dir$file | grep -v "#" | grep -v '^ *$'                                           >> $CREATE_FILE 2>&1
			if [ `cat $dir$file | grep -v "#" | grep -v '^ *$' | grep "\+" |  wc -l` -gt 0 ]
			then
				let u_17_bad_flag=$u_17_bad_flag+1
				echo "결과 : + 설정 값이 존재합니다. (취약)"                                                             >> $CREATE_FILE 2>&1
				echo " "                                                             >> $CREATE_FILE 2>&1
			else
				echo "설정 내용이 없습니다."                                                           >> $CREATE_FILE 2>&1
			fi
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		fi
	done
done
if [ ! -f rhosts.txt ]
then
	echo ".rhosts 파일이 없습니다."                                                              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
if [ $u_17_flag == 3 ]
	then
		if [ $u_17_bad_flag -gt 0 ]
		then
			echo [결과] N                                                                          >> $CREATE_FILE 2>&1
		else
			echo [결과] N                                                                          >> $CREATE_FILE 2>&1
		fi
else
	echo [결과] Y                                                                          >> $CREATE_FILE 2>&1 
fi 
rm -rf rhosts.txt
rm -rf u_17.txt


echo "[U-17 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}


U_18() {
echo "[U-18 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.14 접속 IP 및 포트 제한 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             2.14 접속 IP 및 포트 제한             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/hosts.deny 파일에 All Deny(ALL:ALL) 설정이 등록되어 있고,"                  >> $CREATE_FILE 2>&1
echo "■       : /etc/hosts.allow 파일에 접근 허용 IP가 등록되어 있으면 양호"                   >> $CREATE_FILE 2>&1
echo "■ 	  : 별도의 서버 접근제어 솔루션 운영 시 양호 처리 " 									>> $CREATE_FILE 2>&1
echo "접속 IP 및 포트 제한 TIP"                  >> $CREATE_FILE 2>&1
echo "xinetd는 기본적으로 tcp-wrapper을 내장하고있음"    >> $CREATE_FILE 2>&1
echo  "tcpd라는 tcp_wrapper의 데몬에 의해 접속 제어를 받게됨"     >> $CREATE_FILE 2>&1
echo  "tcpd - /etc/hosts.allow : 접속허용 정책" 					>> $CREATE_FILE 2>&1
echo         "/etc/hosts.deny  : 접속실패 정책"                  >> $CREATE_FILE 2>&1
echo  "즉 tcpd가 설치되지 않았거나 디렉터리가 존재하지 않는다면 tcp-wrapper을 사용하지 않는것임"		>> $CREATE_FILE 2>&1
echo  "우선순위는 allow(우선) > deny "		>> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/hosts.allow 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_18_flag=0
if [ -f /etc/hosts.allow ]
then
	if [ ! `cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$'                                       >> $CREATE_FILE 2>&1
		if [ `cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$' | grep -i "all" | wc -l` -gt 0 ]
		then
			echo "all 설정이 존재합니다 (취약)"                                                             >> $CREATE_FILE 2>&1
			let u_18_flag=$u_18_flag+30
		fi
	else
		echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.allow 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
	let u_18_flag=$u_18_flag+1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/hosts.deny 파일 설정"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.deny ]
then
	if [ ! `cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$'                                        >> $CREATE_FILE 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.deny 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	let u_18_flag=$u_18_flag+1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! -f /etc/hosts.allow ] && [ ! -f /etc/hosts.deny ];
then
	echo [결과] N	                                                                           >> $CREATE_FILE 2>&1
elif [ $u_18_flag -ge 30 ] 
then
	echo [결과] N	                                                                           >> $CREATE_FILE 2>&1
elif [ $u_18_flag -ge 0 ]
then
	echo [결과] M	                                                                           >> $CREATE_FILE 2>&1
fi 

echo "[U-18 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_55() {
echo "[U-55 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.15 host.lpd 파일 소유자 및 권한 설정 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.15 host.lpd 파일 소유자 및 권한 설정    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이면 양호"                   >> $CREATE_FILE 2>&1
echo "hosts.lpd 파일 소유자 및 권한설정 TIP"                  >> $CREATE_FILE 2>&1
echo  "hosts.lpd = 프린터서버에서 클라이언트를 지정하는파일"     >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.lpd ]
then
	ls -alL /etc/hosts.lpd                                                                        >> $CREATE_FILE 2>&1
	echo " "                                                                         	        	 >> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/hosts.lpd | grep "...-.-----" | wc -l` -eq 1 ]

	then
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
	else
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1
	fi
else
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-55 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}
# 2021 년도 항목에서 제외
# U_56() { #
# echo "[U-56 Start]"                                                                              >> $CREATE_FILE 2>&1
# echo "################## 2.16 NIS 서비스 비활성화 ###########################################"
# echo "#######################################################################################" >> $CREATE_FILE 2>&1
# echo "##################              2.16 NIS 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
# echo "#######################################################################################" >> $CREATE_FILE 2>&1
# echo "■ 기준: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우 양호"            >> $CREATE_FILE 2>&1
# echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
# echo " "                                                                                       >> $CREATE_FILE 2>&1
# SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nids"

# if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
# then
# 	echo "☞ NIS, NIS+ Service Disable"                                                        >> $CREATE_FILE 2>&1
# 	flag=Y
# else
# 	echo "☞ NIS+ 데몬은 rpc.nids임"														   >> $CREATE_FILE 2>&1
# 	ps -ef | egrep $SERVICE | grep -v "grep"                                                   >> $CREATE_FILE 2>&1
	
# 	if [ `ps -ef | grep "rpc.nids" | grep -v "grep" | wc -l` -eq 0 ]
# 	then
# 		echo " "                                                                                       >> $CREATE_FILE 2>&1
# 		echo "NIS 서비스가 구동 중입니다. (인터뷰)"                  											   >> $CREATE_FILE 2>&1
# 		echo " "                                                                                       >> $CREATE_FILE 2>&1
# 		flag=M

# 	else
# 		flag=Y
# 	fi
# fi
# echo " "                                                                                       >> $CREATE_FILE 2>&1
# 	echo [결과] $flag                                                                          >> $CREATE_FILE 2>&1

# echo " "                                                                                       >> $CREATE_FILE 2>&1
# echo " "                                                                                       >> $CREATE_FILE 2>&1
# echo "[U-56 End]"                                                                                >> $CREATE_FILE 2>&1
# echo "#######################################################################################" >> $CREATE_FILE 2>&1
# echo "=======================================================================================" >> $CREATE_FILE 2>&1
# echo " "                                                                                       >> $CREATE_FILE 2>&1
# echo " "                                                                                       >> $CREATE_FILE 2>&1
# }

U_56() {
echo "[U-56 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.17 UMASK 설정 관리 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                2.17 UMASK 설정 관리               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: UMASK 값이 022 이상이면 양호"                                                        >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
U_56_flag_not_existed=0
cp /dev/null U_56_flag.txt 
echo "현재 umask"                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
umask       >> $CREATE_FILE 2>&1
if [ `umask` -ge 22 ]
then
	echo "양호" > U_56_flag.txt 
	echo "양호합니다"                               >> $CREATE_FILE 2>&1
fi 


echo "① /etc/profile 파일(권고 설정: umask 022)"                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
	if [ `cat /etc/profile | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -A 1 -B 1 -i umask | grep -v ^#                                 >> $CREATE_FILE 2>&1
	else
		echo "umask 설정이 없습니다."                                                              >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/profile 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 계정별 환경파일 umask 설정값 확인"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
		# echo "☞ $dir 디렉토리 내 환경파일 확인"                        							                                >> $CREATE_FILE 2>&1
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		
		if [ -f $dir/.profile ]
		then
			echo " - $dir/.profile 파일 존재, umask 설정값 확인"				       			                         >> $CREATE_FILE 2>&1
			cat $dir/.profile | egrep "^umask|^#umask"                                                      		  >> $CREATE_FILE 2>&1
			if [ `cat $dir/.profile | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.profile | egrep "^#umask" | wc -l` -ne 0 ] #umask가 잇고  umask가 없는 경우 
				then
					echo "umask가 주석입니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			elif [ `cat $dir/.profile | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.profile | egrep "^#umask" | wc -l` -eq 0 ] #umask도  잇고  umask가 없는 경우 
				then
					echo "umask가 설정되어 있지 않습니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			else #umask가 있는 경우
				if [ `cat $dir/.profile | egrep "umask" | awk -F" " '{ print $2}'` -gt 22 ] 
				then
						
						echo "양호합니다"                               >> $CREATE_FILE 2>&1
						echo "양호" >> U_56_flag.txt 
				else 	
						echo "umask가 022가 아닙니다. (M/T)"                         >> $CREATE_FILE 2>&1					
				fi

			fi 


		
		fi
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		for item in `ls $dir/.*shrc 2>&1` 
		do 
		if [ -f $item ]
			then
			
			echo " - $item 파일 존재, umask 설정값 확인"				       			                         >> $CREATE_FILE 2>&1
			
			cat $item | egrep "^umask|^#umask"                                                      		  >> $CREATE_FILE 2>&1
			
			if [ `cat $item | egrep "^umask" | wc -l` -eq 0 -a `cat $item | egrep "^#umask" | wc -l` -ne 0 ] #umask가 잇고  umask가 없는 경우 
				then
					echo "umask가 주석입니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			elif [ `cat $item | egrep "^umask" | wc -l` -eq 0 -a `cat $item | egrep "^#umask" | wc -l` -eq 0 ] #umask도  잇고  umask가 없는 경우 
				then
					
					echo "umask가 설정되어 있지 않습니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			else #umask가 있는 경우
				if [ `cat $item | egrep "umask" | awk -F" " '{ print $2}'` -gt 22 ] 
				then
						
						echo "양호합니다"                               >> $CREATE_FILE 2>&1
						echo "양호" >> U_56_flag.txt 
				else 	
						echo "umask가 022가 아닙니다. (M/T)"                         >> $CREATE_FILE 2>&1					
				fi
			fi 


			echo " "                                                                                       >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------"				       			                         >> $CREATE_FILE 2>&1
		fi
		done
		
	
	
		if [ -f $dir/.login ]
		then
			echo " - $dir/.login 파일 존재, umask 설정값 확인"				       			                         >> $CREATE_FILE 2>&1
			cat $dir/.login | egrep "^umask|^#umask"                                                      		  >> $CREATE_FILE 2>&1
			if [ `cat $dir/.login | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.login | egrep "^#umask" | wc -l` -ne 0 ] #umask가 잇고  umask가 없는 경우 
				then
					echo "umask가 주석입니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			elif [ `cat $dir/.login | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.login | egrep "^#umask" | wc -l` -eq 0 ] #umask도  잇고  umask가 없는 경우 
				then
					echo "umask가 설정되어 있지 않습니다"                        >> $CREATE_FILE 2>&1
					U_56_flag_not_existed=1
			else #umask가 있는 경우
				if [ `cat $dir/.login | egrep "umask" | awk -F" " '{ print $2}'` -gt 22 ] 
				then
						
						echo "양호합니다"                               >> $CREATE_FILE 2>&1
						echo "양호" >> U_56_flag.txt 
				else 	
						echo "umask가 022가 아닙니다. (M/T)"                         >> $CREATE_FILE 2>&1					
				fi
			fi 


			echo " "                                                                                       >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------"				       			                         >> $CREATE_FILE 2>&1
		fi
		
		if [ -f $dir/.bash_profile ]
			then
				echo " - $dir/.bash_profile 파일 존재, umask 설정값 확인"				       			                         >> $CREATE_FILE 2>&1
				cat $dir/.bash_profile | egrep "^umask|^#umask"                                                      		  >> $CREATE_FILE 2>&1
				if [ `cat $dir/.bash_profile | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.bash_profile | egrep "^#umask" | wc -l` -ne 0 ] #umask가 잇고  umask가 없는 경우 
					then
						echo "umask가 주석입니다"                                        >> $CREATE_FILE 2>&1
						U_56_flag_not_existed=1
				elif [ `cat $dir/.bash_profile | egrep "^umask" | wc -l` -eq 0 -a `cat $dir/.bash_profile | egrep "^#umask" | wc -l` -eq 0 ] #umask도  잇고  umask가 없는 경우 
					then
						echo "umask가 설정되어 있지 않습니다"                                        >> $CREATE_FILE 2>&1
						U_56_flag_not_existed=1
				else #umask가 있는 경우
					if [ `cat $dir/.bash_profile | egrep "umask" | awk -F" " '{ print $2}'` -gt 22 ] 
					then
							
							echo "양호합니다"                               >> $CREATE_FILE 2>&1
							echo "양호" >> U_56_flag.txt 
					else 	
							echo "umask가 022가 아닙니다. (M/T)"                         >> $CREATE_FILE 2>&1					
					fi
				fi 


				echo " "                                                                                       >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------"				       			                         >> $CREATE_FILE 2>&1

		fi
		
	fi

done


if [ `cat U_56_flag.txt | grep "양호" | wc -l` -eq 0 ]
then
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] M	                                                                           >> $CREATE_FILE 2>&1
else
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] Y	                                                                           >> $CREATE_FILE 2>&1
fi

rm -f U_56_flag.txt 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-56 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_57() {
echo "[U-57 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.18 홈 디렉토리 소유자 및 권한 설정 ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.18 홈 디렉토리 소유자 및 권한 설정       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고,"   >> $CREATE_FILE 2>&1
echo "■       : 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"                                 >> $CREATE_FILE 2>&1
echo "■		  : 홈 디렉터리 소유자가 해당 계정이고, 일반 사용자 쓰기 권한이 제거된 경우 양호 " >> $CREATE_FILE 2>&1
echo "홈 디렉토리 소유자 및 권한 설정 TIP"                  >> $CREATE_FILE 2>&1
echo "UID가 500을 넘어가는 계정을 중점 확인[그이하는 시스템 계정]"     >> $CREATE_FILE 2>&1
echo "홈디렉터리가 존재하는 계정중 소유자, 퍼미션확인 그외사용자가 쓰기 권한을 가지면 안됨"    >> $CREATE_FILE 2>&1

echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 사용자 홈 디렉터리"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
U_57_flag=0
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp"  | grep -v "var" | grep -v "news" | grep -v "uucppublic" | egrep -v "/sbin|/root|/var/spool/|/var/adm|/var/empty/sshd|/usr/games|/bin" | uniq`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
		ls -dal $dir | grep '\d.........'                                                          >> $CREATE_FILE 2>&1
	fi
done
echo ""                                                          >> $CREATE_FILE 2>&1
echo "☞ CENTOS, REDHOT 계열 UID 500이상 확인"     >> $CREATE_FILE 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 500 || $3 == 500 {print $6}' | grep -wv "\/" | sort -u`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
		ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
		if [ ! `ls -dal $dir |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
		then
			let U_57_flag=U_57_flag+1
		fi

	fi
done
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 기타 리눅스 계열 UID 100이상 확인" >> $CREATE_FILE 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 100 || $3 == 100 {print $6}' | grep -wv "\/" | sort -u`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
    	ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
		if [ ! `ls -dal $dir |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
		then
			let U_57_flag=U_57_flag+1
		fi    	
    fi
done

echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $U_57_flag -gt 1 ]
then 
	echo [결과] N	                                                                           >> $CREATE_FILE 2>&1
else
	echo [결과] Y	                                                                           >> $CREATE_FILE 2>&1
fi 
                                                                                      >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-57 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_58() {
echo "[U-58 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.19 홈 디렉토리로 지정한 디렉토리의 존재 관리 #####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.19 홈 디렉토리로 지정한 디렉토리의 존재 관리   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호"                         >> $CREATE_FILE 2>&1
echo "예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음."                         >> $CREATE_FILE 2>&1
# 홈 디렉토리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
# 예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음.
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 홈 디렉터리가 존재하지 않은 계정"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | grep -v "/var/ftp" | uniq`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
	then
		awk -F: '$6=="'${dir}'" { print "● 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd        >> $CREATE_FILE 2>&1
		echo " "                                                                                   > U_58_user_check.txt
	fi
done

if [ ! -f U_58_user_check.txt ]
then
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되지 않았습니다. (양호)"                        >> $CREATE_FILE 2>&1
	echo [결과] Y																		>> $CREATE_FILE 2>&1
else
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되었습니다. (취약)"                        >> $CREATE_FILE 2>&1
	echo [결과] M																		>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-58 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -f U_58_user_check.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_59() {
echo "[U-59 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.20 숨겨진 파일 및 디렉토리 검색 및 제거 ##########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.20 숨겨진 파일 및 디렉토리 검색 및 제거      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 디렉토리 내에 숨겨진 파일을 확인 및 검색 하여 , 불필요한 파일 존재 경우 삭제 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /tmp -name ".*" -ls                                                                       > U_59_hidden_file_and_directory.txt
find /home -name ".*" -ls                                                                      >> U_59_hidden_file_and_directory.txt
find /usr -name ".*" -ls                                                                       >> U_59_hidden_file_and_directory.txt
find /var -name ".*" -ls                                                                       >> U_59_hidden_file_and_directory.txt
head -1000 U_59_hidden_file_and_directory.txt                                                                           >> $CREATE_FILE 2>&1

U_59_flag_num=`cat U_59_hidden_file_and_directory.txt | wc -l`
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "확인해야할 파일 및 디렉토리 개수 : "$U_59_flag_num                                                              >> $CREATE_FILE 2>&1
if [ $U_59_flag_num -eq 0 ]
then
	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1

else
	echo "위에 리스트에서 숨겨진 파일 확인"                                                        >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
rm -f U_59_hidden_file_and_directory.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-59 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_19() {
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################     3. 서비스 관리     ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "[U-19 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.1 finger 서비스 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.1 finger 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Finger 서비스가 비활성화 되어 있을 경우 양호"                                    >> $CREATE_FILE 2>&1
echo "finger 서비스는 시스템의 사용자정보를 확인하는 서비스"                     >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo "Finger 서비스 비활성화 TIP"                                       >> $CREATE_FILE 2>&1
echo "finger-server가 구동되면 TCP 79번 포트가 오픈되며"                        >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d/finger 파일이 생성된다"                                   >> $CREATE_FILE 2>&1
ech "/etc/xinetd.conf 가 없으면 xinetd가 설정되지 않은 것 "              >> $CREATE_FILE 2>&1
echo "해당 항목은 finger-server 가 구동되었는지를 뭍는 질문이기때문에"          >> $CREATE_FILE 2>&1
echo "79번포트의 상태와 /etc/xinetd.d/finger 파일의 존재여부를 확인해야함" 			 >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d/finger 파일의 DISABLE = YES로 설정되어있다면 양호함"                           >> $CREATE_FILE 2>&1
echo "항목의 취지는 원격지에서 finger root@192.168.232.135 와 같은 명령으로"                       >> $CREATE_FILE 2>&1
echo "원격지에서 79번포트를 이용하여 계정정보를 탐색할수있는 행위를 차단하기위함"                  >> $CREATE_FILE 2>&1
echo "즉 finger 포트인 79번 포트의 LISTEN을 차단해야함"                                            >> $CREATE_FILE 2>&1

echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_19_flag=0

if [ ! $os_version -eq 1 ]
then
	if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]
		then
			echo "☞ Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
		else
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
		fi
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		u_19_flag=`netstat -na | grep ":$port " | grep -i "^tcp" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`                         >> $CREATE_FILE 2>&1
	else
		if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]
		then
			echo "☞ Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
		else
			netstat -na | grep ":79 " | grep -i "^tcp"                                                >> $CREATE_FILE 2>&1
		fi
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		u_19_flag=`netstat -na | grep ":79 " | grep -i "^tcp" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`                		         >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1


else # solaris


    echo "☞ finger 서비스 활성화 상태"                                                                         >> $CREATE_FILE 2>&1
    echo "--------------------------------------------------------------------"                                 >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo "☞ svcs 명령 점검"                                                                                    >> $CREATE_FILE 2>&1
      
    if [ `cat solaris_command_list.txt | grep -i "svcs" | wc -l` -eq 0 ]
    then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
    else
      svcs -a | grep -i 'finger'                                                                                >> $CREATE_FILE 2>&1
      if [ ! `svcs -a | grep -i 'finger' | grep -i 'online' | wc -l` -eq 0 ]
      then
        let u_19_flag=u_19_flag+1
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    echo "☞ inetadm 명령 점검"                                                                                 >> $CREATE_FILE 2>&1
      
    if [ `cat solaris_command_list.txt | grep -i "inetadm" | wc -l` -eq 0 ]
    then
      echo "inetadm 명령이 존재하지 않습니다."                                                                  >> $CREATE_FILE 2>&1
    else
      inetadm | grep -i 'finger'                                                                                >> $CREATE_FILE 2>&1
      if [ ! `inetadm | grep -i 'finger' | grep -i 'online' | wc -l` -eq 0 ]
      then
        let u_19_flag=u_19_flag+1
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    echo "☞ /etc/inetd.conf 파일 설정 내역"                                                                    >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    
    if [ -f /etc/inetd.conf ]
    then  
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      cat /etc/inetd.conf | grep -i 'finger'                                                                    >> $CREATE_FILE 2>&1
      if [ ! `cat /etc/inetd.conf | grep -i 'finger' | grep '#' | wc -l` -eq 0 ]
       then
        let u_19_flag=u_19_flag+1
      fi
    else
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      echo "/etc/inetd.conf 파일이 존재하지 않습니다."                                                          >> $CREATE_FILE 2>&1
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1


fi 
if [ $u_19_flag -gt 0 ] 
then
	echo [결과] N                                                                    >> $CREATE_FILE 2>&1
else
	echo [결과] Y                                                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-19 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_20() {
echo "[U-20 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.2 Anonymous FTP 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.2 Anonymous FTP 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호"                            >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호"  >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_20_flag=0

cat ftpinfo.txt >> $CREATE_FILE 2>&1
echo " "                                                                >> $CREATE_FILE 2>&1

if [ -f ftpenable.txt ] && [ `cat ftpenable.txt | grep "enable" | wc -l` -gt 0 ];
then
		flag1="Enabled"
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		echo "③ Anonymous FTP 설정 확인"                                                              >> $CREATE_FILE 2>&1
		echo "---------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
		if [ -s vsftpd.txt ]
		then
			cat $vsfile | grep -i "anonymous_enable" | awk '{print "● VsFTP 설정: " $0}'                 >> $CREATE_FILE 2>&1
			echo " "                                                                                     >> $CREATE_FILE 2>&1
			
			if [ `cat $vsfile | grep -i "anonymous_enable" | grep -i "YES" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'` -ne 0 ]
			then
				flag2=N
				echo "anonymous_enable=YES입니다. (취약) "                                                                                     >> $CREATE_FILE 2>&1
				echo " "                                                                                     >> $CREATE_FILE 2>&1
			fi

		elif [ -s proftpd.txt ]
		then
			echo "-------------------proftpd.conf--------------------------------------"        >> $CREATE_FILE 2>&1
			cat $profile                                                                        >> $CREATE_FILE 2>&1
			echo "---------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
			if [ `cat $profile | grep "<Anonymous " | wc -l` -gt 0 ]
			then
				echo "Anonymous 설정이 있습니다"                                                                                     >> $CREATE_FILE 2>&1	
				flag2=N
			else
				flag2=M
			fi
		else
			if [ `cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l` -gt 0 ]
			then
				echo "● ProFTP, 기본FTP 설정:"                                                               >> $CREATE_FILE 2>&1
				cat /etc/passwd | egrep "^ftp:|^anonymous:"                                                  >> $CREATE_FILE 2>&1
				echo " "                                                                                     >> $CREATE_FILE 2>&1
				flag2=Y
				echo " "                                                                                     >> $CREATE_FILE 2>&1
			else
				echo "● ProFTP, 기본FTP 설정: /etc/passwd 파일에 ftp 또는 anonymous 계정이 없습니다."        >> $CREATE_FILE 2>&1
				echo " "                                                                                     >> $CREATE_FILE 2>&1
				flag2=N
			fi	
		fi
else
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
	flag1="Disabled"
	flag2=Y
fi	
if [ $flag1 == "Disabled" ]
then
	echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
else
	echo [결과] $flag2                                                                  >> $CREATE_FILE 2>&1
fi
                                                                                         >> $CREATE_FILE 2>&1    

rm -rf U-20_ftp.txt
rm -rf U-20_ftpps.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-20 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_21() {
echo "[U-21 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.3 r 계열 서비스 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.3 r 계열 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "rsh-server 을 설치하게되면 /etc/xinetd.d/rsh , rlogin, rexe 가 설치되며"                   >> $CREATE_FILE 2>&1
echo "구동시 포트가 각각 오픈된다 포트번호는 아래와 같다."                                       >> $CREATE_FILE 2>&1
echo "TCP 512번포트 = rexec 서비스[etc/xinetd.d/rexec"                                           >> $CREATE_FILE 2>&1
echo "TCP 513번포트 = rlogin 서비스[etc/xinetd.d/rlogin"               			       >> $CREATE_FILE 2>&1
echo "TCP 514번포트 = rsh 서비스[etc/xinetd.d/rsh"                                               >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_21_flag=0
if [ ! $os_version -eq 1 ] # not solaris
then
	echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > rcommand.txt
		fi
	fi

	if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > rcommand.txt
		fi
	fi

	if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > rcommand.txt
		fi
	fi

else # solaris 

    echo "① r 계열 서비스 현황"                                                                                >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo "☞ svcs 명령 점검"                                                                                    >> $CREATE_FILE 2>&1
     
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
    else
      svcs -a | grep -i 'rlogin'                                                                                >> $CREATE_FILE 2>&1
      if [ ! `svcs -a | grep -i 'rlogin' | grep -i 'online' | wc -l` -eq 0 ]
       then
        let U_21_flag=U_21_flag+1
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    echo "☞ inetadm 명령 점검"                                                                                 >> $CREATE_FILE 2>&1
    
    if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -eq 0 ]
     then
      echo "inetadm 명령이 존재하지 않습니다."                                                                  >> $CREATE_FILE 2>&1
    else
      inetadm | egrep 'shell|login|exec|rsh|rlogin|rexec' | egrep -v  'klogin|kshell|kexec'                     >> $CREATE_FILE 2>&1
      if [ ! `inetadm | egrep 'shell|login|exec|rsh|rlogin|rexec' | egrep -v 'klogin|kshell|kexec' | grep -i 'online' | wc -l` -eq 0 ]
       then
      let U_21_flag=U_21_flag+1
      fi
    fi
 
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    
fi 

if [ $U_21_flag -gt 0 ]
then
	rm -rf rcommand.txt
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "불필요한 r 서비스는 삭제해야 합니다 "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo [결과] N										 																									   >> $CREATE_FILE 2>&1
else
	echo "☞ r-commands Service Disable"                                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo [결과] Y																																		   >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-21 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_22() {
echo "[U-22 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.4 cron 파일 소유자 및 권한설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.4 cron 파일 소유자 및 권한설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: crobtab 명령의 권한이 750 이하 및 cron.allow 또는 cron.deny 파일 권한이 640 미만이면 양호"                         >> $CREATE_FILE 2>&1
echo "■       : (cron.allow 또는 cron.deny 파일이 없는 경우 슈퍼유저계정만 cron 명령을 사용가능)" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "crontab 파일 권한 확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_22_flag=0

if [ -f /usr/bin/crontab ]
then
	ls -alL /usr/bin/crontab                                                                      >> $CREATE_FILE 2>&1
	if [ `ls -alL /usr/bin/crontab | awk -F" " '{print $1}' | grep '......-----' | wc -l` -eq 0 -o `ls -alL /usr/bin/crontab | awk -F" " '{ print $3 }'` != "root" ]
	then
		echo "Permission not satisfied"                                                 >> $CREATE_FILE 2>&1
		u_22_flag=1 # BAD
	else
		echo "/usr/bin/crontab 권한 양호"                                                 >> $CREATE_FILE 2>&1
	fi 
else
	echo "/usr/bin/crontab 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
	u_22_flag=3 # M/T 
	
fi
if [ ! $os_version -eq 1 ] # not solaris
then
	cron_path=/etc/ 
else
	cron_path=/etc/cron.d/ # solaris 
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① cron.allow 파일 권한 확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f "$cron_path"cron.allow ]
then
	ls -alL "$cron_path"cron.allow                                                                      >> $CREATE_FILE 2>&1
	if [ `ls -alL "$cron_path"cron.allow | awk -F" " '{print $1}' | grep '...-.-----' | wc -l` -eq 0 -o `ls -alL "$cron_path"cron.allow | awk -F" " '{ print $3 }'` != "root" ]
	then
		echo "Permission not satisfied"                                                 >> $CREATE_FILE 2>&1
		u_22_flag=1 # BAD
	else
		echo "$cron_path"cron.allow 권한 양호                                                 >> $CREATE_FILE 2>&1
	fi 
else
	echo "$cron_path"cron.allow 파일이 없습니다.                                                      >> $CREATE_FILE 2>&1
	u_22_flag=1 # BAD
	
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② cron.deny 파일 권한 확인"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f "$cron_path"cron.deny ]
then
	ls -alL "$cron_path"cron.deny                                                                       >> $CREATE_FILE 2>&1
	if [ `ls -alL "$cron_path"cron.deny | awk -F" " '{print $1}' | grep '...-.-----' | wc -l` -eq 0 -o `ls -alL "$cron_path"cron.deny | awk -F" " '{ print $3 }'` != "root" ]
	then
		echo "Permission not satisfied"                                                 >> $CREATE_FILE 2>&1
		u_22_flag=1 # BAD
	else
		echo "$cron_path"cron.deny 권한 양호                                                 >> $CREATE_FILE 2>&1
	fi 
else
	echo "$cron_path"cron.deny 파일이 없습니다.                                                       >> $CREATE_FILE 2>&1
	u_22_flag=1 # BAD
fi

echo ""                                                                                       >> $CREATE_FILE 2>&1

echo "사용자별 cron 파일 권한 확인"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /var/spool/cron/crontabs/ ]
then

	ls -alL /var/spool/cron/crontabs/    | egrep -v "^d"          >  tmp022.txt  # directory 제외
	echo " "																				 >> $CREATE_FILE 2>&1
	for file in `awk -F" " '{ print $9 }' tmp022.txt`
	do
		
		if [ "$file" == "." ] || [ "$file" == ".." ]
		then
			continue
		fi
		ls -alL /var/spool/cron/crontabs/$file >> $CREATE_FILE 2>&1
	
		if [ `ls -alL /var/spool/cron/crontabs/$file | awk -F" " '{ print $1 }' | grep "...-.-----" | wc -l` -eq 0 -o `ls -alL /var/spool/cron/crontabs/$file | awk -F" " '{ print $3 }'` != "root" ]
		then
			echo "Permission Not satisfied" >> $CREATE_FILE 2>&1
			u_22_flag=1 # BAD
		fi	
	done

else 
	echo "/var/spool/cron/crontabs/ 디렉터리가 없습니다"									 >> $CREATE_FILE 2>&1
fi 
echo ""    
rm -rf tmp022.txt
if [ $u_22_flag == 1 ]
then
	echo [결과] N                                                                  >> $CREATE_FILE 2>&1
else
	echo [결과] M                                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-22 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_23() {
echo "[U-23 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.5 Dos 공격에 취약한 서비스 비활성화 ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.5 Dos 공격에 취약한 서비스 비활성화       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DoS 공격에 취약한 echo , discard , daytime , chargen  서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $CREATE_FILE 2>&1
echo "먼저 해당서비스를 설치하려면 rsh-server 패키지를설치해야하며 서비스를 구동하게되면 각각의 "                     >> $CREATE_FILE 2>&1
echo "포트들이 오픈되게 되는데 이포트를 통해 DOS 공격을 시도될수있다.PORT가 오픈되지 않으면 DOS공격을 할수없음"       >> $CREATE_FILE 2>&1
echo "먼저 가장먼저 봐야할것은 서비스 포트가 오픈되어있는지 확인후 서비스구동여부를 확인한다. "                       >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d/경로에서 파일을 DISABLE 설정하던가 /etc/service 에서 서비스를 주석처리하여 차단해도된다"          >> $CREATE_FILE 2>&1
echo "중요한것은 포트가 구동되어있으면 안된다."									      >> $CREATE_FILE 2>&1
echo "echo      = TCP와 UDP 소통을 위해 7번포트를 사용하며 이것은 디버깅 및 측량 도구로 구현되었으며"			>> $CREATE_FILE 2>&1
echo "수신한 데이터를 송신한 호스트로 돌려 보내는 작업을 수행, 따라서 서비스 거부 공격 가능성이 매우높음"                   >> $CREATE_FILE 2>&1
echo "daytime	= time과 같은 기능을 수행하지만 사람이 읽기 쉬운 형태로 제공하는 것이 다름, 이서비스는 13번포트에서 실행 "   >> $CREATE_FILE 2>&1                                                  
echo "chargen    = 19번 포트에서 동작하며 tcp와udp를 사용함 tcp에서 동작하는 동안 연결을 기다리다가 연결이되면 연결을 요청한" >> $CREATE_FILE 2>&1
echo " 곳에서 연결을 끊을 때까지 데이터 스트림을 계속 송신한다. udp 상에서 동작할 경우에는 데이터 그램이 수신되기를 "        >> $CREATE_FILE 2>&1
echo "기다린다. 하나의 데이터그램이 수신되면0~512개 문자로 이루어진 데이터 그램으로 응답한다. 서비스 거부 공격에 자주 사용"  >> $CREATE_FILE 2>&1
echo "discard    = 9번 포트를 통해서 TCP 및 UDP 에서 동작 이것은 디버깅 도구로서 개발되었다. 서비스 용도는 수신하는 모든 데이터를 버리는 것이다."    >> $CREATE_FILE 2>&1                                                                             >> $CREATE_FILE 2>&1
echo "/etc/service 에서 서비스를 주석처리하였다면 반드시 xinetd 서비스를 재시작해야 포트가 내려간다."			  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1

if [ ! $os_version -eq 1 ] # not solaris
then
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
	cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > unnecessary.txt
		fi
	fi

	if [ -f unnecessary.txt ]
	then
		rm -rf unnecessary.txt
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		echo [결과] N										 																									   >> $CREATE_FILE 2>&1
	else
		echo "불필요한 서비스가 동작하고 있지 않습니다.(echo, discard, daytime, chargen)"            >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		echo [결과] Y										 																									   >> $CREATE_FILE 2>&1
	fi
else # solaris 

	cp /dev/null U-23_Doss.txt
    echo "① DoS 취약 서비스 현황"                                                                              >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo "☞ svcs 명령 점검"                                                                                    >> $CREATE_FILE 2>&1
     
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
    else
      svcs -a | egrep -i "echo|daytime|discard|chargen"                                                         >> $CREATE_FILE 2>&1
      if [ `svcs -a | egrep -i "echo|daytime|discard|chargen" | grep -i 'online' | wc -l` -eq 0 ]
       then
        echo "양호"                                                                         >> U-23_Doss.txt
      else
        echo "취약"                                                                         >> U-23_Doss.txt
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    echo "☞ inetadm 명령 점검"                                                                                 >> $CREATE_FILE 2>&1
      
    if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -eq 0 ]
     then
      echo "inetadm 명령이 존재하지 않습니다."                                                                  >> $CREATE_FILE 2>&1
    else
      inetadm | egrep -i "echo|daytime|discard|chargen"                                                         >> $CREATE_FILE 2>&1
      if [ `inetadm | egrep -i "echo|daytime|discard|chargen" | grep -i 'online' | wc -l` -eq 0 ]
       then
        echo "양호"                                                                         >> U-23_Doss.txt
      else
        echo "취약"                                                                         >> U-23_Doss.txt
      fi
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    if [ `cat U-23_Doss.txt | grep "취약" | wc -l` -eq 0 ]
      then
      echo [결과] Y										 																									   >> $CREATE_FILE 2>&1
      else
        echo [결과] N										 																									   >> $CREATE_FILE 2>&1
    fi
fi	
rm -f U-23_Doss.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1                                                                                     >> $CREATE_FILE 2>&1
echo "[U-23 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_24() {
echo "[U-24 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.6 NFS 서비스 비활성화 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.6 NFS 서비스 비활성화               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ ! $os_version -eq  1 ] # linux
then

	echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
	 then
	   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
	 else
	   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② NFS Client Daemon(statd,lockd)확인"                                                   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd" | wc -l` -gt 0 ] 
	  then
	    ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd"                    >> $CREATE_FILE 2>&1
	  else
	    echo "☞ NFS Client(statd,lockd) Disable"                                                  >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 제거되어 있는 경우 양호"                         >> $CREATE_FILE 2>&1
	echo "■ REPORT"                                                                                  >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
	 then
	   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
	   flag1="Enabled_Server"
	 else
	   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
	   flag1="Disabled_Server"
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② NFS Client Daemon(statd,lockd)확인"                                                   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd" | wc -l` -gt 0 ] 
	  then
	    ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd"            >> $CREATE_FILE 2>&1
	    flag2="Enabled_Client"
	  else
	    echo "☞ NFS Client(statd,lockd) Disable"                                                  >> $CREATE_FILE 2>&1
	    flag2="Disabled_Client"
	fi

	if [ $flag1 == "Disabled_Server" -a $flag2 == "Disabled_Client" ]
	then
		echo [결과] Y                                                                  >> $CREATE_FILE 2>&1
		
	else
		
		echo [결과] M                                                                  >> $CREATE_FILE 2>&1
	fi                                                                                   >> $CREATE_FILE 2>&1

else # solaris

    echo "① NFS Server 서비스 현황"                                                                            >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    cp /dev/null U-24_check_NFS.txt
    
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
      
      if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -eq 0 ]
       then
        echo "inetadm 명령이 존재하지 않습니다."                                                                >> $CREATE_FILE 2>&1
       else
         inetadm | grep -i "nfs/server"                                                                         >> $CREATE_FILE 2>&1
         if [ `inetadm | grep -i "nfs/server" | grep -i 'online' | wc -l` -eq 0 ]
          then
           echo "양호"                                                                      >> U-24_check_NFS.txt
           echo "NFS server 서비스가 비 실행중입니다."                                                          >> $CREATE_FILE 2>&1
          else
                echo "② /etc/dfs/dfstab 현황"                                                                  >> $CREATE_FILE 2>&1
               echo "------------------------------------------------------------------------------"            >> $CREATE_FILE 2>&1
                  if [ -f /etc/dfs/dfstab ]
                  then
                      cat /etc/dfs/dfstab                                                                       >> $CREATE_FILE 2>&1
                  else
                      echo "/etc/dfs/dfstab 파일이 존재하지 않습니다."                                          >> $CREATE_FILE 2>&1
                      echo "취약"                                                           >> U-24_check_NFS.txt
                  fi
              echo " "                                                                                          >> $CREATE_FILE 2>&1
              echo "③ /etc/dfs/sharetab 현황"                                                                  >> $CREATE_FILE 2>&1
              echo "------------------------------------------------------------------------------"             >> $CREATE_FILE 2>&1
                  if [ -f /etc/dfs/sharetab ]
                  then
                      cat /etc/dfs/sharetab                                                                     >> $CREATE_FILE 2>&1
                  else
                      echo "/etc/dfs/sharetab 파일이 존재하지 않습니다."                                        >> $CREATE_FILE 2>&1
                      echo "취약"                                                           >> U-24_check_NFS.txt
                  fi
         fi
      fi
    
    else
      svcs -a | grep -i "nfs/server"                                                                            >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      
      if [ `svcs -a | grep -i "nfs/server" | grep -i 'online' | wc -l` -eq 0 ]
       then
        echo "양호"                                                                         >> U-24_check_NFS.txt
        echo "NFS server 서비스가 비 실행중입니다."                                                             >> $CREATE_FILE 2>&1
      else
       echo "② /etc/dfs/dfstab 현황"                                                                           >> $CREATE_FILE 2>&1
       echo "------------------------------------------------------------------------------"                    >> $CREATE_FILE 2>&1
        if [ -f /etc/dfs/dfstab ]
         then
           cat /etc/dfs/dfstab                                                                                  >> $CREATE_FILE 2>&1
        else
           echo "/etc/dfs/dfstab 파일이 존재하지 않습니다."                                                     >> $CREATE_FILE 2>&1
           echo "취약"                                                                      >> U-24_check_NFS.txt
        fi
        
       echo " "                                                                                                 >> $CREATE_FILE 2>&1
       echo "③ /etc/dfs/sharetab 현황"                                                                         >> $CREATE_FILE 2>&1
       echo "------------------------------------------------------------------------------"                    >> $CREATE_FILE 2>&1
        if [ -f /etc/dfs/sharetab ]
         then
           cat /etc/dfs/sharetab                                                                                >> $CREATE_FILE 2>&1
        else
           echo "/etc/dfs/sharetab 파일이 존재하지 않습니다."                                                   >> $CREATE_FILE 2>&1
           echo "취약"                                                                      >> U-24_check_NFS.txt
        fi
      
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
    if [ `cat U-24_check_NFS.txt | grep "취약" | wc -l` -eq 0 ]
      then
      	
        echo [결과] Y                                                                  >> $CREATE_FILE 2>&1
      else
        echo [결과] M                                                                  >> $CREATE_FILE 2>&1
    fi

fi 
echo "[U-24 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_25() {
echo "[U-25 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.7 NFS 접근 통제 ##################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                3.7 NFS 접근 통제                 ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준1: 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everone 공유를 제한한 경우"                                           >> $CREATE_FILE 2>&1
echo "■ 기준2: NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
# (취약 예문) /tmp/test/share *(rw)

if [ ! $os_version -eq 1 ]
then
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	flag1=M
	if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
	 then
	   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
	   flag1=M
	 else
	   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
	   flag1="Disabled"
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② /etc/exports 파일 설정"                                                               >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/exports ]
	then
		if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
		then
			cat /etc/exports | grep -v "^#" | grep -v "^ *$"                                           >> $CREATE_FILE 2>&1
			if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | grep "everyone" wc -l` -ne 0 ]
			then
				echo "everyone 공유 설정이 존재합니다. (취약)"                                                               >> $CREATE_FILE 2>&1	
				flag2=N
			else
				flag2=Y
			fi
		else
			echo "/etc/expports 내 everyone설정이 없습니다."                                                               >> $CREATE_FILE 2>&1
			flag2=Y

		fi
	else
	  echo "/etc/exports 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
	fi

	echo " "                                                                                       >> $CREATE_FILE 2>&1
	if [ $flag1 == "Disabled" ]
	then
		echo [결과] Y                                                                         >> $CREATE_FILE 2>&1

	else
		echo [결과] $flag2                                                                  >> $CREATE_FILE 2>&1
	fi
else # solaris

	cp /dev/null U-25_permission_NFS.txt
	echo "① NFS Server / Client 서비스 현황"                                                                   >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo "☞ svcs 명령 점검"                                                                                    >> $CREATE_FILE 2>&1
    
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
    else
      svcs -a | egrep -i "nfs/server|nfs/client"                                                                >> $CREATE_FILE 2>&1
      if [ `svcs -a | egrep -i "nfs/server|nfs/client" | grep -i 'online' | wc -l` -eq 0 ]
       then
        echo "양호"                                                                         >> U-25_permission_NFS.txt
      else
        echo "구동 중"                                                                         >> U-25_permission_NFS.txt
      fi
    fi
    
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    echo "☞ inetadm 명령 점검"                                                                                 >> $CREATE_FILE 2>&1

    if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -eq 0 ]
     then
      echo "inetadm 명령이 존재하지 않습니다."                                                                  >> $CREATE_FILE 2>&1
    else
      inetadm | egrep -i "nfs/server|nfs/client"                                                                >> $CREATE_FILE 2>&1
      if [ `inetadm | egrep -i "nfs/server|nfs/client" | grep -i 'online' | wc -l` -eq 0 ]
       then
        echo "양호"                                                                         >> U-25_permission_NFS.txt
      else
        echo "구동 중"                                                                         >> U-25_permission_NFS.txt
      fi
    fi
    
    if [ `cat U-25_permission_NFS.txt | grep "구동 중" | wc -l` -eq 0 ]
      then
        echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
      else
      	if [ -f /etc/dfs/dfstab ]
      	then 
      		echo "----------/etc/dfs/dfstab-----------"                                             >> $CREATE_FILE 2>&1
      		cat /etc/dfs/dfstab                                             >> $CREATE_FILE 2>&1
      	fi
      	if [ -f /etc/dfs/sharetab ]
      	then 
      		echo "----------/etc/dfs/sharetab-----------"                                             >> $CREATE_FILE 2>&1
      		cat /etc/dfs/sharetab                                             >> $CREATE_FILE 2>&1
      	fi
        echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
    fi
    
fi 

rm -f U-25_permission_NFS.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-25 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_26() {
echo "[U-26 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.8 automountd 제거 ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.8 automountd 제거                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: automountd 서비스가 동작하지 않을 경우 양호"                                     >> $CREATE_FILE 2>&1
echo "automountd 제거 TIP"                                                         >> $CREATE_FILE 2>&1
echo "automountd를 구동하기위해선 autofs 패키지를 설치해야한다."                    >> $CREATE_FILE 2>&1
echo "automountd 가 구동되어있다면 대게 rpc서비스와 nfs 서비스와 필수적으로 관련되기때문에 해당프로세스가 구동되어있을 확률이높다." >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① Automountd Daemon 확인"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] 
 then
   ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"              >> $CREATE_FILE 2>&1
   flag=N
 else
   echo "☞ Automountd Daemon Disable"                                                         >> $CREATE_FILE 2>&1
   flag=Y
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] $flag                                                                            >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-26 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_27() {
echo "[U-27 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.9 RPC 서비스 확인 ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.9 RPC 서비스 확인                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 rpc 관련 서비스가 존재하지 않으면 양호"                                 >> $CREATE_FILE 2>&1
echo "리눅스는 inetd.conf파일에 설정되어있는 방식과 /etc/xinetd.d/ 디렉토리안에 파일형태로 설정되어있는 2가지 방식이 존재한다."  >> $CREATE_FILE 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.sprayd|rpc.rstatd|rpc.rexd|rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd|rpc.rwalld|rpc.rusersd"

if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -eq 0 ]
      then
        echo " /etc/xinetd.d 디렉토리에 불필요한 서비스가 없음" >> $CREATE_FILE 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
    fi
  else
     echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/inetd.conf ]
  then
	echo "# cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD" >> $CREATE_FILE 2>&1
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않음 " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo " " > rpc.txt

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "취약" >> rpc.txt
          else
           echo "양호" >> rpc.txt
        fi
        done
    else
      echo "양호" >> rpc.txt
    fi
fi

if [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
              then
                 echo "양호" >> rpc.txt
              else
                 echo "취약" >> rpc.txt
    fi
fi


if [ `cat rpc.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo [결과] Y >> $CREATE_FILE 2>&1
 else
  echo [결과] N >> $CREATE_FILE 2>&1
fi

rm -rf rpc.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-27 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_28() {
echo "[U-28 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.10 NIS , NIS+ 점검 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.10 NIS , NIS+ 점검                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "■ 기준: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS +를 사용하는 경우 > 양호"                                 >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1

U_28_FLAG=""
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nids"

if [ ! $os_version -eq 1 ] # linux
then
	if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ NIS, NIS+ Service Disable"                                                        >> $CREATE_FILE 2>&1
		U_28_FLAG=Y
	else
		echo "☞ NIS+ 데몬은 rpc.nids임"														   >> $CREATE_FILE 2>&1
		ps -ef | egrep $SERVICE | grep -v "grep"                                                   >> $CREATE_FILE 2>&1
		
		if [ `ps -ef | grep "rpc.nids" | grep -v "grep" | wc -l` -eq 0 ]
		then
			echo " "                                                                                       >> $CREATE_FILE 2>&1
			echo "NIS 서비스가 구동 중입니다. "                  											   >> $CREATE_FILE 2>&1
			echo " "                                                                                       >> $CREATE_FILE 2>&1
			U_28_FLAG=N

		else
			U_28_FLAG=Y
		fi
	fi

else # solaris

    SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
    
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      echo "ps 명령을 통해 확인합니다. "                                                                        >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
      then
          echo "NIS, NIS+ 서비스가 비실행중입니다."                                                             >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          U_28_FLAG=Y
      else
          ps -ef | egrep $SERVICE | grep -v "grep"                                                              >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          U_28_FLAG=N
      fi 
    else
    svcs -a | grep -i "nis"                                                                                     >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
	    if [ `svcs -a | grep -i "nis" | grep "online" |  wc -l` -eq 0 ]
	      then
	        echo "NIS, NIS+ 서비스가 비실행중입니다."                                                               >> $CREATE_FILE 2>&1
	        echo " "                                                                                                >> $CREATE_FILE 2>&1
	        U_28_FLAG=Y
	      else
	        echo " "                                                                                                >> $CREATE_FILE 2>&1
	        U_28_FLAG=N
	    fi
    fi
fi 

echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] $U_28_FLAG                                                                          >> $CREATE_FILE 2>&1

echo " "                                                                              >> $CREATE_FILE 2>&1
echo "[U-28 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_29() {
echo "[U-29 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.11 tftp, talk 서비스 비활성화 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.11 tftp, talk 서비스 비활성화          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우에 양호"                         >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "  " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_29_flag=""
if [ ! $os_version -eq 1 ] # linux
then
	if [ `cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > u_29.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > u_29.txt
		fi
	fi
	if [ `cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^udp"                                             >> $CREATE_FILE 2>&1
			echo " "                                                                                   > u_29.txt
		fi
	fi
	echo " "                                                  >> $CREATE_FILE 2>&1
	if [ -f u_29.txt ]
	then
		rm -rf u_29.txt
		echo "업무상 필요한지 확인이 필요합니다. (취약) "                                                  >> $CREATE_FILE 2>&1
		echo " "                                                  >> $CREATE_FILE 2>&1
		u_29_flag=N
	else
		echo "☞ tftp, talk, ntalk Service Disable"                                                  >> $CREATE_FILE 2>&1
		u_29_flag=Y
	fi
else # solaris

    if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -eq 0 ]
     then
      echo "inetadm 명령이 존재하지 않습니다."                                                                  >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      echo "ps 명령을 통해 확인합니다. "                                                                        >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      if [ `ps -ef | egrep -i "tftp|talk|ntalk" | grep -v "grep" | wc -l` -eq 0 ]
      then
          echo "tffp, talk 서비스가 비실행중입니다."                                                            >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          u_29_flag=Y
      else
          ps -ef | egrep -i "tftp|talk|ntalk" | grep -v "grep"                                                  >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          u_29_flag=N
      fi 
    
    else
      inetadm | egrep -i "tftp|talk|ntalk"                                                                      >> $CREATE_FILE 2>&1
      if [ `inetadm | egrep -i "tftp|talk|ntalk" | grep "online" |  wc -l` -eq 0 ]
      then
        echo "tffp, talk 서비스가 비실행중입니다."                                                              >> $CREATE_FILE 2>&1
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        u_29_flag=Y
      else
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        u_29_flag=N
      fi
    fi


fi 
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] $u_29_flag                                                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-29 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_30() {
echo "[U-30 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.12 Sendmail 버전 점검 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.12 Sendmail 버전 점검               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: sendmail 버전이 8.13.8 이상이면 양호"                                            >> $CREATE_FILE 2>&1
echo "Sendmail이 설치되지 않았는데 25번포트를 LISTEN하고 있다면 CentOS6, REDHOT 최신버전은 sendmail이 아닌 postfix 라는 메일서비스를 사용함"   >> $CREATE_FILE 2>&1
echo "Sendmail 버전 점검 TIP"																	>> $CREATE_FILE 2>&1
echo "postfix 는 구조자체가 Sendmail과 다르므로 Sendmail 항목과 맞춰서 진단하기는 곤란함  N/A처리함"      >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $CREATE_FILE 2>&1



echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	flag1=M
	ps -ef | grep sendmail | grep -v grep														>> $CREATE_FILE 2>&1
	echo " "                                                                                  	 >> $CREATE_FILE 2>&1
	
	echo "② sendmail 버전확인"                                                                  >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	   	then
	    grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ                                          >> $CREATE_FILE 2>&1
	    if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ | egrep "8\.15\.2|8\.14\." | wc -l` -eq 1 ]
	    then
	    	echo "버전이 8.13 이상입니다"                                                                                  	 >> $CREATE_FILE 2>&1
	    	flag1=Y
	    else
	    	flag1=M
	    fi

	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
	flag1=Y
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[참고]"                                                                              	   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "/etc/services 파일에서 포트 확인"                                                     	 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $os_version -eq 1 ]
then
	echo "서비스 포트 활성화 여부 확인"                                                        		 >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		else
			echo "☞ Sendmail Service Disable"                                                         >> $CREATE_FILE 2>&1
		fi
	else
		echo "서비스 포트 확인 불가" 				                                                         >> $CREATE_FILE 2>&1
	fi
fi
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "postfix 서비스 여부 체크"                                                     	 >> $CREATE_FILE 2>&1
echo " "                                                     	 >> $CREATE_FILE 2>&1
if [ `ps -ef | grep /usr/libexec/postfix/master | wc -l` -gt 0 ] #postfix 가 살아있음
then
	echo "postfix 가 열려있습니다. smtp 를 사용할 확률이 높습니다" 				                                                         >> $CREATE_FILE 2>&1
fi 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo [결과] $flag1                                                                           >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-30 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_31() {
echo "[U-31 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.13 스팸 메일 릴레이 제한 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.13 스팸 메일 릴레이 제한             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■       : (R$*         $#error $@ 5.7.1 $: "550 Relaying denied" 해당 설정에 주석이 제거되어 있으면 양호)" >> $CREATE_FILE 2>&1
echo "스팸 메일 릴레이 제한 TIP" 																>> $CREATE_FILE 2>&1
echo "일부 relay 를 풀어 주기 위해서 sendamil.cf 를 변경 하는 사람들이 있는데 이럴 경우 spammer 들의 표적이 되어  "		>> $CREATE_FILE 2>&1
echo "다른 메일 서버로 부터 reject 을 당할수가 있으니 sendmail.cf 를 변경하여 전체 relay 를 푸면 안됨."	 >> $CREATE_FILE 2>&1
echo "OK = [host에서지정된] 메일의 모든것을 허용[relay]한다. "									>> $CREATE_FILE 2>&1
echo "RELAY = [host에서지정된]메일의 수신/발신을 허용한다."									>> $CREATE_FILE 2>&1
echo "REJECT = [host에서지정된]메일의 수신/발신을 거부한다."									>> $CREATE_FILE 2>&1
echo "DISCARD = /etc/sendmail.cf에 시정된 $#discard mailer에 지정된곳으로 메일을 폐기함.(발신자는 메일일 발신된것으로 알게됨."  >> $CREATE_FILE 2>&1
echo "501 <message> 지정된 user@host 와 발신자의 주소가 전체 혹은 부분적으로 일치할 경우 이메일을 받지 않는다. "			 >> $CREATE_FILE 2>&1
echo "553 <message> 발신자의 주소에 호스트명이 없을 경우 메일을 받지 않는다."							>> $CREATE_FILE 2>&1
echo "550 <message> 지정된 도메인과 관련된 메일을 받지 않는다."									>> $CREATE_FILE 2>&1
echo "보통 아주 간단한 예로서 111.111.111.111 이라는 pc 에서 메일을 발송하기를 원한다면"					 >> $CREATE_FILE 2>&1
echo "111.111.111.111		RELAY"												 >> $CREATE_FILE 2>&1
echo "라는 한줄을 설정해 주는 것으로 메일을 발송을 할수 있다."									 >> $CREATE_FILE 2>&1
echo "예제]  cyberspammer.com        REJECT"											 >> $CREATE_FILE 2>&1
echo "예제]  sendmail.org            OK"  										 >> $CREATE_FILE 2>&1
echo "예제]  128.32                  RELAY"											 >> $CREATE_FILE 2>&1
echo "예제]  localhost.localdomain   RELAY"											 >> $CREATE_FILE 2>&1
echo "예제]  localhost               RELAY"											 >> $CREATE_FILE 2>&1
echo "예제]   127.0.0.1              RELAY"											 >> $CREATE_FILE 2>&1
echo "예제]  linux.rootman.org                     REJECT"                                >> $CREATE_FILE 2>&1
echo "예제]  linux.rootman.org                     501 Oh.. No.. linux.rootman.org"                                             >> $CREATE_FILE 2>&1
echo "예제]  linux.rootman.org                     571 You are spammer.. "                                                     >> $CREATE_FILE 2>&1
echo "/etc/mail/access 에서 RELAY 설정을 마친 후에는 access.db 를 갱신해 줘야 한다."						 >> $CREATE_FILE 2>&1
echo "makemap hash /etc/mail/access < /etc/mail/access"									   >> $CREATE_FILE 2>&1
echo "명령을 실행하여 갱신을 할수가 있다. access 파일을 수정시에는 sendmail을 재시작 할"					   >> $CREATE_FILE 2>&1
echo "필요는 없으며 makemap 을 이용하여 access.db 만 갱신해 주면 바로 적용이 된다."						  >> $CREATE_FILE 2>&1
echo "DB에 정상적으로 저장되었는지 확인하는 명령어는 다음과 같다 strings access.db | grep 192"					 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	ps -ef | grep sendmail | grep -v grep														 >> $CREATE_FILE 2>&1
	flag1="Enabled"
	echo " "                                                                                  	 >> $CREATE_FILE 2>&1
	
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "② /etc/mail/sendmail.cf 파일의 옵션 확인"                                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
	    cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"                         >> $CREATE_FILE 2>&1
	    if [ `cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" | grep -v ^# | wc -l` -eq 0 ]
	    then
		    echo "설정이 취약합니다. (취약)"                                            >> $CREATE_FILE 2>&1
		    flag2=N	
	  	else
	  		flag2=Y	
	  	fi 
	    
	  else
		echo "/etc/mail/sendmail.cf 파일이 없습니다."                                            >> $CREATE_FILE 2>&1
	    flag2=M
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "③ sendmail 버전확인"                                                                    >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	   then
	     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ                                          >> $CREATE_FILE 2>&1
	   else
	     echo "/etc/mail/sendmail.cf 파일이 없습니다."                                           >> $CREATE_FILE 2>&1
	fi
else
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                     >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[참고]"                                                                              	   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "/etc/services 파일에서 포트 확인"                                                    		 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $os_version -eq 1 ]
then
	echo "서비스 포트 활성화 여부 확인"                                                       	   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		else
			echo "☞ Sendmail Service Disable"                                                         >> $CREATE_FILE 2>&1
		fi
	else
		echo "서비스 포트 확인 불가" 				                                                         >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag1 == "Disabled" ]
then
	echo [결과] Y                                                     >> $CREATE_FILE 2>&1
else
	echo [결과] $flag2                                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-31 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_32() {
echo "[U-32 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.14 일반사용자의 Sendmail 실행 방지 ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       3.14 일반사용자의 Sendmail 실행 방지        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■       : (PrivacyOptions=authwarnings,restrictqrun 옵션이 설정되어 있을 경우 양호)"                                 >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	ps -ef | grep sendmail | grep -v grep														>> $CREATE_FILE 2>&1
	flag1="Enabled"
	echo " "                                                                                  	 >> $CREATE_FILE 2>&1
	
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "② /etc/mail/sendmail.cf 파일의 옵션 확인"                                             >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
	    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                               >> $CREATE_FILE 2>&1
	    if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep restrictqrun | wc -l` -eq 0 ] 
	    then
	    	echo "restrictqrun 설정이 부족합니다"                                      >> $CREATE_FILE 2>&1
	    	flag2=N
	    else
	    	flag2=Y
	    fi 

	  else
	    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                            >> $CREATE_FILE 2>&1
	    flag2="Null"
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[참고]"                                                                              	   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "/etc/services 파일에서 포트 확인"                                                    		 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $os_version -eq 1 ] # linux
then
	echo "서비스 포트 활성화 여부 확인"                                                        		 >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		else
			echo "☞ Sendmail Service Disable"                                                         >> $CREATE_FILE 2>&1
		fi
	else
		echo "서비스 포트 확인 불가" 				                                                         >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                     >> $CREATE_FILE 2>&1
if [ $flag1 == "Disabled" ]
then
	echo [결과] Y                                                     >> $CREATE_FILE 2>&1
else
	echo [결과] $flag2                                                                  >> $CREATE_FILE 2>&1
fi                                                                           >> $CREATE_FILE 2>&1
echo "[U-32 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_33() {
echo "[U-33 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.15 DNS 보안 버전 패치 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.15 DNS 보안 버전 패치               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호"           >> $CREATE_FILE 2>&1
echo "■       : (양호한 버전: 8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)"            >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`

DNSPR=`echo $DNSPR | awk '{print $1}'`

if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
then
	
	flag1=M
	if [ -f $DNSPR ]
	then
    echo "BIND 버전 확인"                                                                      >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
    $DNSPR -v | grep BIND                                                                      >> $CREATE_FILE 2>&1
  else
    echo "$DNSPR 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
  fi
else
  echo "☞ DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
  flag1=Y
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] $flag1  																		>> $CREATE_FILE 2>&1
echo "[U-33 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_34() {
echo "[U-34 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.16 DNS Zone Transfer 설정 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.16 DNS Zone Transfer 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"           >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
u_34_zone_fransfer_flag=0
u_34_zone_fransfer_flag2=2
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
	u_34_zone_fransfer_flag=2
else
	ps -ef | grep named | grep -v "grep"                                                         >> $CREATE_FILE 2>&1
	u_34_zone_fransfer_flag=3
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ls -al /etc/rc.d/rc*.d/* 2>/dev/null | grep -i named | grep "/S" | wc -l` -gt 0 ] #  No such file or directory 가 나오면 rc*.d/ 내 아무 파일도 없다는 뜻
then
	ls -al /etc/rc.d/rc*.d/* 2>/dev/null | grep -i named | grep "/S"                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi

if [ -f /etc/rc.tcpip ]
then
	cat /etc/rc.tcpip | grep -i named                                                            >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "② /etc/named.conf 파일의 allow-transfer 확인 (BIND8 DNS 설정)"                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.conf ]
then
	cat /etc/named.conf | grep 'allow-transfer'                                                  >> $CREATE_FILE 2>&1
	if [ `cat /etc/named.conf | grep 'allow-transfer' | wc -l` -ne 0 ]
	then
	u_34_zone_fransfer_flag2=1
	echo " "                                                      >> $CREATE_FILE 2>&1
	echo "transfer 설정이 되어 있지 않습니다"                                                      >> $CREATE_FILE 2>&1
	
	fi
elif [ -f /etc/bind/named.conf ]
	then
	if [ `cat /etc/bind/named.conf | grep 'allow-transfer' | wc -l` -ne 0 ]
	then
	u_34_zone_fransfer_flag2=1
	echo " "                                                      >> $CREATE_FILE 2>&1
	echo "transfer 설정이 되어 있지 않습니다"                                                      >> $CREATE_FILE 2>&1
	fi
else
	echo "named.conf 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/named.boot 파일의 xfrnets 확인 (BIND4.9 DNS 설정)"                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.boot ]
then
	cat /etc/named.boot | grep "\xfrnets"                                                        >> $CREATE_FILE 2>&1
	u_34_zone_fransfer_flag2=1
else
	echo "/etc/named.boot 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi

if [ $u_34_zone_fransfer_flag -eq 2 ]
then

	echo [결과] Y                                                                            >> $CREATE_FILE 2>&1
else

	echo [결과] ${FLAG_TABLE[$u_34_zone_fransfer_flag2]}                                            >> $CREATE_FILE 2>&1
fi

echo "[U-34 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_35() {
echo "[U-35 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.17 Apache 디렉토리 리스팅 제거 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.17 Apache 디렉토리 리스팅 제거          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_35_flag1=0
u_35_flag2=0
if [ ! $apaflag -eq 0 ]
then
	u_35_flag1="Enabled"
	echo "☞ httpd 데몬 동작 확인"                                                         		 >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	ps -ef | grep "httpd" | grep -v "grep"                                					     >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "☞ httpd 설정파일 경로"                                                          		 >> $CREATE_FILE 2>&1
	if [ -f Inf_apaTemp.txt ]
	then
		cat Inf_apaTemp.txt                                                           			 >> $CREATE_FILE 2>&1
		rm -rf Inf_apaTemp.txt
	fi
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	echo $ACONF																					 >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	
	if [ -f $ACONF ]
	then
		echo "☞ Indexes 설정 확인"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"    >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                     >> $CREATE_FILE 2>&1
		echo " "                                                                                 >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#'                   >> $CREATE_FILE 2>&1

		if [ `cat $ACONF | grep -v " *#" | grep "Options" | wc -l` -ne 0 ] 
		then

			if [ `cat $ACONF | grep -v " *#" | grep "Options" | grep "Indexes" | wc -l` -gt 0 ]
			then
				u_35_flag2=1
				echo "☞ Options에 Indexes 설정이 존재합니다.(취약)"                                  >> $CREATE_FILE 2>&1

			else
				u_35_flag2=2
			fi
		else
			u_35_flag2=3
		fi


		# u_35_flag2=`cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#' | grep Indexes | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $CREATE_FILE 2>&1
		u_35_flag2=3
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_35_flag1=Y
	u_35_flag2=3
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $u_35_flag1 == "Disabled" ]
then
	
	echo [결과] Y			                                                                  >> $CREATE_FILE 2>&1
else
	echo [결과] ${FLAG_TABLE[$u_35_flag2]}                                                      >> $CREATE_FILE 2>&1
fi
                                                                                          >> $CREATE_FILE 2>&1
echo "[U-35 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_36() {
echo "[U-36 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.18 Apache 웹 프로세스 권한 제한 ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.18 Apache 웹 프로세스 권한 제한          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"      >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_36_flag=0
if [ ! $apaflag -eq 0 ]
then
	u_36_flag=3
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1	
	
	cat $ACONF | grep -i "^user"                                                                 >> $CREATE_FILE 2>&1
	cat $ACONF | grep -i "^group"                                                                >> $CREATE_FILE 2>&1

	if [ $apache_type == "httpd" ]
	then
		usercheck=`cat $ACONF | grep -i "^User" | awk -F" " '{print $2}'`
		groupcheck=`cat $ACONF | grep -i "^Group" | awk -F" " '{print $2}'`

		if [ `echo $usercheck | grep "root" | grep $rootuser | wc -l` -ne 0 -o `echo $groupcheck | grep "root" | grep $rootuser | wc -l` -ne 0 ]
		then
			u_36_flag=1
			echo " "                                                                                   >> $CREATE_FILE 2>&1
			echo "☞ 프로세스 권한이 슈퍼 유저로 되어 있습니다. (취약)"                                                           >> $CREATE_FILE 2>&1

		else
			u_36_flag=2
		fi

	elif [ $apache_type == "apache2" ]
	then
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		echo "☞ envvars 파일 설정 확인"                                                           >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^User" | awk '{print $2}' | sed 's/[${}]//g'`  >> $CREATE_FILE 2>&1	
		cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^Group" | awk '{print $2}' | sed 's/[${}]//g'` >> $CREATE_FILE 2>&1	
		
		usercheck=`cat $AHOME/envvars | grep -i cat $ACONF | grep -i "^User" | awk '{print $2}' | sed 's/[${}]//g'` | awk -F"=" '{print $2}'
		
		groupcheck=`cat $AHOME/envvars | grep -i cat $ACONF | grep -i "^Group" | awk '{print $2}' | sed 's/[${}]//g'` | awk -F"=" '{print $2}'
		
		if [ `echo $usercheck | grep "root" | grep $rootuser | wc -l` -ne 0 -o `echo $groupcheck | grep "root" | grep $rootuser | wc -l` -ne 0 ]
		then

			u_36_flag=1
			echo " "                                                                                   >> $CREATE_FILE 2>&1
			echo "☞ 프로세스 권한이 슈퍼 유저로 되어 있습니다. (취약)"                                                           >> $CREATE_FILE 2>&1

		else
			u_36_flag=2
		fi

	else 
		u_36_flag=3
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "☞ $apache_type 데몬 동작 계정 확인"                                                   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	
	ps -ef | grep $apache_type | grep -v grep                                                    >> $CREATE_FILE 2>&1
	
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_36_flag=3
	
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] ${FLAG_TABLE[$u_36_flag]}                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                                         >> $CREATE_FILE 2>&1
echo "[U-36 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_37() {
echo "[U-37 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.19 Apache 상위 디렉토리 접근 금지 ################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.19 Apache 상위 디렉토리 접근 금지        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 AllowOverride None 설정이 아니면 양호"        >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_37_flag1=0
u_37_flag2=0
if [ ! $apaflag -eq 0 ]
then
	u_37_flag1=3
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#'                 >> $CREATE_FILE 2>&1
		u_37_flag2=`cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#' | grep AllowOverride | awk -F" " '{print $2}' | grep -v none | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
		echo " "                                  >> $CREATE_FILE 2>&1
		echo "AllowOverride None 값이 존재합니다. (취약)"                                  >> $CREATE_FILE 2>&1
		echo " "                                  >> $CREATE_FILE 2>&1
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $CREATE_FILE 2>&1
		u_37_flag1=3
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_37_flag1=2
	
fi

if [ $u_37_flag1 == 4 ]
then
	echo [결과] Y			                                                                  >> $CREATE_FILE 2>&1
elif [ $u_37_flag2 -gt 0 ]
then
	echo [결과] N                                                      >> $CREATE_FILE 2>&1

else 
	echo [결과] Y                                                      >> $CREATE_FILE 2>&1
fi

echo "[U-37 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_38() {
echo "[U-38 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.20 Apache 불필요한 파일 제거 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.20 Apache 불필요한 파일 제거          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /htdocs/manual 또는 /apache/manual 디렉터리와,"                                  >> $CREATE_FILE 2>&1
echo "■       : /cgi-bin/test-cgi, /cgi-bin/printenv 파일이 제거되어 있는 경우 양호"           >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1=M
	echo "☞ ServerRoot Directory" 	 	                                                           >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"      	 >> $CREATE_FILE 2>&1
	echo $AHOME																																									 >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "☞ DocumentRoot Directory" 	                                                           >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"    		 >> $CREATE_FILE 2>&1
	if [ $apache_type = "httpd" ]
	then
		DOCROOT=`cat $ACONF | grep -i ^DocumentRoot | awk '{print $2}' | sed 's/"//g'` 2>&1
		echo $DOCROOT																																							 >> $CREATE_FILE 2>&1
	elif [ $apache_type = "apache2" ]
	then
		cat $AHOME/sites-enabled/*.conf | grep -i "DocumentRoot" | awk '{print $2}' | uniq         > apache2_DOCROOT.txt 2>&1
		cat apache2_DOCROOT.txt																																		 >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	find $AHOME -name "*cgi-bin*" -exec ls -l {} \;
	find $AHOME -name "*cgi-bin*" -exec ls -l {} \;																								 > unnecessary_file.txt 2>&1
	find $AHOME -name "*printenv*" -exec ls -l {} \;																							 >> unnecessary_file.txt 2>&1
	find $AHOME -name "*manual*" -exec ls -ld {} \;																								 > unnecessary_directory.txt 2>&1
	
	find $DOCROOT -name "*cgi-bin*" -exec ls -l {} \;																							 >> unnecessary_file.txt 2>&1
	find $DOCROOT -name "*printenv*" -exec ls -l {} \;																						 >> unnecessary_file.txt 2>&1
	
	if [ $apache_type = "apache2" ]
	then
		for docroot2 in `cat ./apache2_DOCROOT.txt`
		do
			find $docroot2 -name "*cgi-bin*" -exec ls -l {} \;																					 >> unnecessary_file.txt 2>&1
			find $docroot2 -name "*printenv*" -exec ls -l {} \;																					 >> unnecessary_file.txt 2>&1
			find $docroot2 -name "*manual*" -exec ls -ld {} \;																					 >> unnecessary_directory.txt 2>&1
		done
	fi
	
		echo "☞ test-cgi, printenv 파일 확인"       					                                     >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		if [ `cat ./unnecessary_file.txt | wc -l` -eq 0 ]
		then
			echo "☞ test-cgi, printenv 파일이 존재하지 않습니다."		                               >> $CREATE_FILE 2>&1
		else
			cat ./unnecessary_file.txt																															 >> $CREATE_FILE 2>&1
		fi
		echo " "                                                                                   >> $CREATE_FILE 2>&1

		echo "☞ manual 디렉토리 확인"				       					                                     >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		if [ `cat ./unnecessary_directory.txt | wc -l` -eq 0 ]
		then
			echo "☞ manual 디렉토리가 존재하지 않습니다."		  				                             >> $CREATE_FILE 2>&1
		else
			cat ./unnecessary_directory.txt																													 >> $CREATE_FILE 2>&1
		fi
		echo " "                                                                                   >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	flag1=Y
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] $flag1                                                                           >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
rm -rf ./unnecessary_file.txt
rm -rf ./unnecessary_directory.txt
echo " "            																			>> $CREATE_FILE 2>&1
echo "[U-38 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_39() {
echo "[U-39 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.21 Apache 링크 사용 금지 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.21 Apache 링크 사용 금지            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_39_flag=0
if [ ! $apaflag -eq 0 ]
then
	u_39_flag=3
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#'                >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1

		if [ `cat $ACONF | grep -v " *#" | grep "Options" | wc -l` -ne 0 ] 
		then

			if [ `cat $ACONF | grep -v " *#" | grep "Options" | grep "Indexes" | wc -l` -gt 0 ]
			then
				u_39_flag=1
				echo "☞ Options에 Indexes 설정이 존재합니다.(취약)"                                  >> $CREATE_FILE 2>&1

			else
				u_39_flag=2
			fi
		else
			u_39_flag=3
		fi
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $CREATE_FILE 2>&1
		u_39_flag=3
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_39_flag=2
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] ${FLAG_TABLE[$u_39_flag]}				                                                                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-39 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_40() {
echo "[U-40 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.22 Apache 파일 업로드 및 다운로드 제한 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.22 Apache 파일 업로드 및 다운로드 제한     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호"     >> $CREATE_FILE 2>&1
echo "■       : <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_40_flag=0
if [ ! $apaflag -eq 0 ]
then
	u_40_flag=3
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#'              >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
		if [ `cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#' | grep LimitRequestBody | wc -l` -eq 0 ]
		then
			echo "☞ LimitRequestBody 설정이 존재하지 않습니다.(취약)"                                  >> $CREATE_FILE 2>&1
			u_40_flag=1

		else
			u40_LimitRequestBody=`cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#' | grep LimitRequestBody | awk -F" " ' { print $2 }'`
			if [ $u40_LimitRequestBody -eq 0 -o $u40_LimitRequestBody -gt 5000000 ]
			then
				echo "☞ LimitRequestBody 설정 값을 확인해야 합니다.(취약)"                                  >> $CREATE_FILE 2>&1
				u_40_flag=1
			fi

		fi
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $CREATE_FILE 2>&1
		u_40_flag=3
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_40_flag=2
	
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo [결과] ${FLAG_TABLE[$u_40_flag]}                                                      >> $CREATE_FILE 2>&1


	
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-40 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_41() {
echo "[U-41 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.23 Apache 웹 서비스 영역의 분리 ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.23 Apache 웹 서비스 영역의 분리         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DocumentRoot를 기본 디렉터리(~/apache/htdocs)가 아닌 별도의 디렉토리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
echo "기본 디렉터리 (var/www/html, /Apache/htdocs) "  				 >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
u_41_flag=0
if [ ! $apaflag -eq 0 ]
then
	u_41_flag=3
	if [ -f $ACONF ]
	then
		echo "☞ DocumentRoot 확인"  		                                                           >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		if [ $apache_type = "httpd" ]
		then
			echo $DOCROOT																																						 >> $CREATE_FILE 2>&1
			if [ `echo $DOCROOT | grep -i "www\/html" | wc -l` -ne 0 -o `echo $DOCROOT | grep -i "apache\/htdocs" | wc -l` -ne 0 ]
			then
				u_41_flag=1
				echo "기본 디렉토리로 설정하였습니다. (취약)"																																	 >> $CREATE_FILE 2>&1
			else 
				u_41_flag=2
			fi

		elif [ $apache_type = "apache2" ]
		then
			for docroot2 in `cat ./apache2_DOCROOT.txt`
			do
				echo $docroot2																																				 >> $CREATE_FILE 2>&1
				if [ `echo $docroot2 | grep -i "www\/html" | wc -l` -ne 0 -o `echo $docroot2 | grep -i "apache\/htdocs" | wc -l` -ne 0 ]
					then
						u_41_flag=1
						echo "기본 디렉토리로 설정하였습니다. (취약)"																																	 >> $CREATE_FILE 2>&1
					break
				fi

			done
			if [ $u_41_flag == 3 ]
			then
				u_41_flag=2
			fi
		fi
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  	 >> $CREATE_FILE 2>&1
		u_41_flag=3
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	u_41_flag=2
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] ${FLAG_TABLE[$u_41_flag]}				                                                                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
rm -rf ./apache2_DOCROOT.txt
echo "[U-41 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_60() {
echo "[U-60 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.24 ssh 원격접속 허용 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.24 ssh 원격접속 허용               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SSH 서비스가 활성화 되어 있으면 양호"                                            >> $CREATE_FILE 2>&1
echo "			: 원격 접속 시 SSH 프로토콜을 사용하는 경우 양호" >> $CREATE_FILE 2>&1
echo "			: 위 판단기준을 적용하기 모호한 경우 22번 포트가 오픈되어 있으면 양호 처리" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① 프로세스 데몬 동작 확인"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
U_60_flag=0
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
		U_60_flag=1
	else
		ps -ef | grep sshd | grep -v "grep"                                                        >> $CREATE_FILE 2>&1
		U_60_flag=2
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "② 서비스 포트 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " " > ssh-result.txt
ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep ^Port | grep -v ^# | wc -l` -gt 0 ]
		then
			cat $file | grep ^Port | grep -v ^# | awk '{print "SSH 설정파일('${file}'): " $0 }'      >> ssh-result.txt
			port1=`cat $file | grep ^Port | grep -v ^# | awk '{print $2}'`
			echo " "                                                                                 > port1-search.txt
		else
			echo "SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)"                      >> ssh-result.txt
			U_60_flag=2
		fi
	fi
done
if [ `cat ssh-result.txt | grep -v "^ *$" | wc -l` -gt 0 ]
then
	cat ssh-result.txt | grep -v "^ *$"                                                          >> $CREATE_FILE 2>&1
else
	echo "SSH 설정파일: 설정 파일을 찾을 수 없습니다."                                           >> $CREATE_FILE 2>&1
	U_60_flag=3
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ ! $os_version -eq 1 ]
then

	echo "③ 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f port1-search.txt ]
	then
		if [ `netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
		then
			echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
			U_60_flag=1
		else
			netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
			U_60_flag=2
		fi
	else
		if [ `netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
		then
			echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
			U_60_flag=1
		else
			netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN"                              >> $CREATE_FILE 2>&1
			U_60_flag=2
		fi
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] ${FLAG_TABLE[$U_60_flag]}				                                                                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-60 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf port1-search.txt
rm -rf ssh-result.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_61() {

echo "[U-61 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.25 ftp 서비스 확인 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.25 ftp 서비스 확인                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

cat ftpinfo.txt >> $CREATE_FILE 2>&1
echo " "                                                                >> $CREATE_FILE 2>&1

if [ -f ftpenable.txt ] && [ `cat ftpenable.txt | grep "enable" | wc -l` -gt 0 ];
then
	
	echo "☞ FTP 가 열려있습니다"                                                                >> $CREATE_FILE 2>&1
	echo " "                					                                      >> $CREATE_FILE 2>&1
	echo [결과] M                					                                      >> $CREATE_FILE 2>&1
else
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
	echo " "                					                                      >> $CREATE_FILE 2>&1
	echo [결과] Y      	    					                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "[U-61 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}


U_62() {
echo "[U-62 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.26 ftp 계정 shell 제한 ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.26 ftp 계정 shell 제한              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스에 /bin/false 쉘이 부여되어 있는 경우"                                       >> $CREATE_FILE 2>&1
echo "■       : ftp 서비스 사용 시 ftp 계정의 Shell을 접속하지 못하도록 설정하였을 경우 양호"  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
cat ftpinfo.txt >> $CREATE_FILE 2>&1
echo " "                                                                >> $CREATE_FILE 2>&1
U_62_flag=0

if [ -f ftpenable.txt ] && [ `cat ftpenable.txt | grep "enable" | wc -l` -gt 0 ];
then
	echo "☞ FTP 가 열려있습니다"                                                                >> $CREATE_FILE 2>&1
	echo " "                					                                      >> $CREATE_FILE 2>&1
else
	U_62_flag=2
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi

if [ $U_62_flag -eq 0 ]
then
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ ftp 계정 쉘 확인(ftp 계정에 false 또는 nologin 설정시 양호)"                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
	then
		cat /etc/passwd | awk -F: '$1=="ftp"'                                                        >> $CREATE_FILE 2>&1

		if [ `cat /etc/passwd | grep -i ftp | awk -F":" '{print $7}' | egrep -i "false|nologin" | wc -l` -eq 0 ]
		then
			echo "ftp 쉘 존재 (취약)"                                                       >> $CREATE_FILE 2>&1
			U_62_flag=1		
		else
			U_62_flag=2
		fi
	else
		echo "ftp 계정이 존재하지 않음.(양호)"                                                       >> $CREATE_FILE 2>&1
		U_62_flag=2
	fi
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] ${FLAG_TABLE[$U_62_flag]}				                                                                   >> $CREATE_FILE 2>&1


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-62 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}


U_63() {
echo "[U-63 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.27 Ftpusers 파일 소유자 및 권한 설정 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.27 Ftpusers 파일 소유자 및 권한 설정       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 미만이면 양호"                     >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■       : [참고] solaris 에서  /etc/ftpusers 와 /etc/ftpd/ftpusers 동시에 존재한다면 하나는 심볼링링크하고 있다"                             >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

U_63_flag=0
flag2=Y
cat ftpinfo.txt >> $CREATE_FILE 2>&1
echo " "                                                                >> $CREATE_FILE 2>&1


if [ -f ftpenable.txt ] && [ `cat ftpenable.txt | grep "enable" | wc -l` -gt 0 ];
then
	# rm -rf ftpenable.txt
	flag1="Enabled"
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ ftpusers 파일 소유자 및 권한 확인"                                                    >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	echo " "                                                                                       > ftpusers.txt
	ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
	for file in $ServiceDIR
	do
		if [ -f $file ]
		then
			
			ls -al $file                                                                              >> ftpusers.txt
		fi
	done
	if [ `cat ftpusers.txt | wc -l` -gt 1 ]
	then
		cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
		
		for file2 in `awk -F" " '{print $9}' ftpusers.txt`
		do
			if [ `ls -al $file2 | awk -F" " '{ print $1}' | grep '...-.-----' | wc -l` -eq 0 -o `ls -l $file2 | awk -F" " '{print $3}'` != "root" ]

			then
				echo "Permission not satisfied"                            >> $CREATE_FILE 2>&1
				let U_63_flag=$U_63_flag+1
			
			
			fi
		done
		
	else
		echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $CREATE_FILE 2>&1
		flag2="F"
	fi

else
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag1 == "Disabled" -a $flag2 == "Disabled" ]
then
	echo [결과] Y                                                                  >> $CREATE_FILE 2>&1
elif [ $flag1 == "Enabled" -a $flag2 == "F" ]
then
	echo [결과] N                                                                  >> $CREATE_FILE 2>&1

elif [ $U_63_flag == 0 -a $flag1 == "Enabled" ]
then
	echo [결과] Y                                                                  >> $CREATE_FILE 2>&1
elif [ $U_63_flag -gt 0 ]
then
	echo [결과] N                                                                  >> $CREATE_FILE 2>&1

else

	echo [결과] M                                                                  >> $CREATE_FILE 2>&1
fi 
echo "[U-63 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf ftpusers.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_64() {
echo "[U-64 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.28 Ftpusers 파일 설정 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.28 Ftpusers 파일 설정              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호"        >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■       : [참고] solaris 에서  /etc/ftpusers 와 /etc/ftpd/ftpusers 동시에 존재한다면 하나는 심볼링링크하고 있다"                             >> $CREATE_FILE 2>&1
echo "Ftpusers 파일 소유자 및 권한설정 TIP"																					>> $CREATE_FILE 2>&1
echo "Ftpusers 파일은 ftp를 사용하는 계정들의 접근을 제한 또는 허용하는 파일인데 SFTP는 SSH와 함께 22번포트를 사용함으로 FTPUSERS 파일이 별도로 존재하지 않는다. " >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
cat ftpinfo.txt >> $CREATE_FILE 2>&1
echo " "                                                                >> $CREATE_FILE 2>&1

if [ -f ftpenable.txt ] && [ `cat ftpenable.txt | grep "enable" | wc -l` -gt 0 ];
then
	# rm -rf ftpenable.txt
	flag1="Enabled"

	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "③ ftpusers 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	echo " "                                                                                       > ftpusers.txt
	ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
	for file in $ServiceDIR
	do
		if [ -f $file ]
		then
			if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]
			then
				echo "● $file 파일내용: `cat $file | grep "root" | grep -v "^#"` 계정이 등록되어 있음."  >> ftpusers.txt
				echo "check"                                                                             > check.txt
				flag2=Y
				
				
			else
				echo "● $file 파일내용: root 계정이 등록되어 있지 않음."                                 >> ftpusers.txt
				echo "check"                                                                             > check.txt
				flag2=N
			fi
		fi
	done
	
	if [ -f check.txt ]
	then
		cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
	else
		echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $CREATE_FILE 2>&1
		flag2="Null"
	fi

else
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag1 == "Disabled" ]
then
	echo [결과] Y                                                     >> $CREATE_FILE 2>&1
else
	echo [결과] $flag2                                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-64 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf ftpusers.txt
rm -rf check.txt
rm -rf ftpinfo.txt
rm -rf ftpenable.txt
rm -rf vsftpd.txt
rm -rf proftpd.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_65() {
echo "[U-65 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.29 at 파일 소유자 및 권한설정 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.29 at 파일 소유자 및 권한설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: at.allow 또는 at.deny 파일 권한이 640 미만이면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (at.allow 또는 at.deny 파일이 없는 경우 root만이 at 명령을 사용할 수 있음)" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① at.allow 파일 권한 확인"                                                              >> $CREATE_FILE 2>&1
echo "---------------- --------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ ! $os_version -eq 1 ]
then
	U_65_flag_check=0
	U_65_flag_check2=0
	if [ -f /etc/at.allow ]
	then
		ls -alL /etc/at.allow                                                                        >> $CREATE_FILE 2>&1
		
		if [ `ls -alL /etc/at.allow | grep "...-.-----" | wc -l` -eq 0 -o `ls -alL /etc/at.allow | awk -F" " '{ print $3 }'` != "root" ]
		then
			echo "Permission not satisfied (취약)"                                                  >> $CREATE_FILE 2>&1	
			let U_65_flag_check2=$U_65_flag_check2+1
			
		fi
	else
		echo "/etc/at.allow 가 없습니다"                                                                                        >> $CREATE_FILE 2>&1
		
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② at.deny 파일 권한 확인"                                                               >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/at.deny ]
	then
		ls -alL /etc/at.deny                                                                         >> $CREATE_FILE 2>&1
		
		if [ `ls -alL /etc/at.deny | grep "...-.-----" | wc -l` -eq 0 -o `ls -alL /etc/at.deny | awk -F" " '{ print $3 }'` != "root" ]
		then
			echo "Permission not satisfied (취약)"                                                  >> $CREATE_FILE 2>&1	
			let U_65_flag_check2=$U_65_flag_check2+1
			
		fi
	else
		echo "/etc/at.deny 가 없습니다"                                                                                        >> $CREATE_FILE 2>&1
		

	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1

	if [ $U_65_flag_check -gt 0 -o $U_65_flag_check2 -gt 0 ]
	then #bad
		echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1	
	else
		echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1	
	fi  
else # solaris

    if [ -f /etc/cron.d/at.allow ]
      then
        echo "/etc/cron.d/at.allow 파일이 존재합니다."                                                          >> $CREATE_FILE 2>&1
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        ls -l /etc/cron.d/at.allow                                                                       >> $CREATE_FILE 2>&1

        echo ""
        cat /etc/cron.d/at.allow                                                                       >> $CREATE_FILE 2>&1

        if [ \( `ls -l /etc/cron.d/at.allow | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/cron.d/at.allow | grep '...-.-----' | wc -l` -eq 1 \) ]; then
              allow_result='true'
          else
              allow_result='false'
          fi
    else
      echo "/etc/cron.d/at.allow 파일이 없습니다."                                                              >> $CREATE_FILE 2>&1
          allow_result='true'
    fi
    
    if [ -f /etc/cron.d/at.deny ]
      then
        
        echo "/etc/cron.d/at.deny 파일이 존재합니다."                                                           >> $CREATE_FILE 2>&1
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        ls -l /etc/cron.d/at.deny                                                                        >> $CREATE_FILE 2>&1

        cat /etc/cron.d/at.deny                                                                       >> $CREATE_FILE 2>&1
        if [ \( `ls -l /etc/cron.d/at.deny | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/cron.d/at.deny | grep '...-.-----' | wc -l` -eq 1 \) ]; then
              deny_result='true'
          else
              deny_result='false'
          fi
    else
      echo "/etc/cron.d/at.deny 파일이 없습니다."                                                               >> $CREATE_FILE 2>&1
          deny_result='true'
    fi
              
    echo " "                                                                                                    >> $CREATE_FILE 2>&1

    if [ $allow_result = 'false' -o $deny_result = 'false' ]
      then
        echo [결과] N          	                                                                 >> $CREATE_FILE 2>&1	
      else
        echo [결과] Y          	                                                                 >> $CREATE_FILE 2>&1	
    fi
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-65 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_66() {
echo "[U-66 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.30 SNMP 서비스 구동 점검 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.30 SNMP 서비스 구동 점검             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"                           >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
# SNMP서비스는 동작시 /etc/service 파일의 포트를 사용하지 않음.
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ ! $os_version -eq 1 ]
then
	if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]
	then
		echo "☞ SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
	else
		echo "☞ SNMP 서비스 활성화 여부 확인(UDP 161)"                                              >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
		netstat -na | grep ":161 " | grep -i "^udp"                                                 >> $CREATE_FILE 2>&1
		echo " "                                                                                       >> $CREATE_FILE 2>&1
		echo [결과] M                                                                         >> $CREATE_FILE 2>&1
	fi


else # solaris
    cp /dev/null snmp_process_check.txt
    
    echo "① SNMP 서비스 구동 여부"                                                                             >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    
    if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -eq 0 ]
     then
      echo "svcs 명령이 존재하지 않습니다."                                                                     >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      echo "ps 명령을 통해 확인합니다. "                                                                        >> $CREATE_FILE 2>&1
      echo " "                                                                                                  >> $CREATE_FILE 2>&1
      if [ `ps -ef | grep snmp | grep -v dmi | grep -v "grep" | wc -l` -eq 0 ]
      then
          echo "snmp 서비스가 비실행중입니다."                                                                  >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
      else
          ps -ef | grep snmp | grep -v dmi | grep -v "grep"                                                     >> $CREATE_FILE 2>&1
          ps -ef | grep snmp | grep -v dmi | grep -v "grep"                                 >> snmp_process_check.txt
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          echo [결과] M                                                                         >> $CREATE_FILE 2>&1
      fi 
    else
    svcs -a | grep -i "snmp" | grep -v "dmi"                                                                    >> $CREATE_FILE 2>&1
    svcs -a | grep -i "snmp" | grep -v "dmi"                                                >> snmp_process_check.txt
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    if [ `svcs -a | grep -i "snmp" | grep -v dmi | grep "online" |  wc -l` -eq 0 ]
      then
        echo "snmp 서비스가 비실행중입니다."                                                                    >> $CREATE_FILE 2>&1
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        echo [결과] Y                                                                         >> $CREATE_FILE 2>&1
      else
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        echo [결과] M                                                                         >> $CREATE_FILE 2>&1
    fi
    fi
fi 

echo " "                                                                                    >> $CREATE_FILE 2>&1
echo "[U-66 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_67() {
echo "[U-67 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.31 snmp 서비스 커뮤티니스트링의 복잡성 설정 ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   3.31 snmp 서비스 커뮤티니스트링의 복잡성 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_67_FLAG=M

if [ ! $os_version -eq 1 ]
then

	snmp_port=`cat /etc/services | awk -F" " '$1=="snmp" {print $1 "   " $2}' | awk -F" " '{print $2}' | grep udp | awk -F"/" '{ print $1 }'`
	echo "snmp 포트번호 : " $snmp_port                                       >> $CREATE_FILE 2>&1
	echo "① SNMP 서비스 활성화 여부 확인(UDP $snmp_port)"                                                >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

	if [ `netstat -na | grep ":$snmp_port " | grep -i "^udp" | wc -l` -eq 0 ]
	then
		echo "☞ SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
		U_67_FLAG="Disabled"
	else
		netstat -na | grep ":$snmp_port" | grep -i "^udp"                                                  >> $CREATE_FILE 2>&1
		U_67_FLAG=M
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② SNMP Community String 설정 값"                                                        >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	snmp_config_list=( "/etc/snmpd.conf" "/etc/snmp/snmpd.conf" "/etc/snmp/conf/snmpd.conf" "/SI/CM/config/snmp/snmpd.conf" )
	for config_name in ${snmp_config_list[@]}; do

	    if [ -f $config_name ]
	    then
	    			echo " "                                                                                     >> $CREATE_FILE 2>&1
					echo " "                                                                                     > snmpd.txt

	                echo $config_name." 파일 설정:" >> $CREATE_FILE 2>&1
	                echo "------------------------------------------------------" >> $CREATE_FILE 2>&1
	                cat $config_name | egrep -i "public|private|com2sec|community" | grep -v "^#" >> $CREATE_FILE 2>&1
	        if [ `cat $config_name | egrep -i "public|private|com2sec|community" | grep -v "^#" | egrep -i "public|private" | wc -l` -ne 0 ]

				then
					echo " "                                                                                     >> $CREATE_FILE 2>&1
					echo "public , private Community 값이 존재합니다. (취약) "                                                                                     > snmpd.txt
					echo " "                                                                                     >> $CREATE_FILE 2>&1
					U_67_FLAG=N
				else
					U_67_FLAG=Y
			fi
		fi
	    
	done
	if [ -f snmpd.txt ]
	then
		rm -rf snmpd.txt
	else
		echo "snmpd.conf 파일이 없습니다."                                                           >> $CREATE_FILE 2>&1
		echo " "                                                                                     >> $CREATE_FILE 2>&1
	fi
else 
    # solaris 10
    if [ `uname -a | grep "5.10" | wc -l` -gt 0 ]; then
	    SNMP_CONF="/etc/sma/snmp/snmpd.conf"
	else if [ `uname -a | grep "5.11" | wc -l` -gt 0 ];
		then
	        SNMP_CONF="/etc/net-snmp/snmp/snmpd.conf"
	    else
		    SNMP_CONF="/etc/snmp/snmpd.conf"
		fi
	fi

    echo "SNMP 설정 파일 내 Community String 점검 "                                                             >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1

    if [ `cat snmp_process_check.txt | grep snmp | wc -l` -gt 0 ]; then
        if [ -f $SNMP_CONF ]; then
            if [ `cat $SNMP_CONF | grep -i "Community" | grep -v "^ *#" | egrep "private|public" | wc -l` -gt 0 ]; then
                echo "$SNMP_CONF 설정 현황"                                                                     >> $CREATE_FILE 2>&1
			    cat $SNMP_CONF | grep -i "Community" | grep -v "^ *#" | egrep "private|public"                  >> $CREATE_FILE 2>&1
                echo " "                                                                                        >> $CREATE_FILE 2>&1
                U_67_FLAG=N
			else
                echo "취약한 Community String이 없습니다."                                                      >> $CREATE_FILE 2>&1
                echo " "                                                                                        >> $CREATE_FILE 2>&1
                U_67_FLAG=Y
			fi
        else
            echo "$SNMP_CONF 파일이 존재하지 않음 "                                                             >> $CREATE_FILE 2>&1
            echo " "                                                                                            >> $CREATE_FILE 2>&1
            U_67_FLAG=Y
        fi
    else
        echo "snmp 서비스가 비실행중입니다."                                                                    >> $CREATE_FILE 2>&1
        echo " "                                                                                                >> $CREATE_FILE 2>&1
        U_67_FLAG=Y
    fi
    
    
fi 
rm -rf snmp_process_check.txt

echo " "	                                                                             >> $CREATE_FILE 2>&1
if [ $U_67_FLAG == "Disabled" ]
then
	echo [결과] Y 																			>> $CREATE_FILE 2>&1
else
	echo [결과] $U_67_FLAG	                                                                         >> $CREATE_FILE 2>&1

fi 

echo "[U-67 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_68() {
echo "[U-68 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.32 로그온 시 경고 메시지 제공 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.32 로그온 시 경고 메시지 제공          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/issue.net과 /etc/motd 파일에 로그온 경고 메시지가 설정되어 있을 경우 양호"  >> $CREATE_FILE 2>&1
echo "		: telnet 서비스가 중지되어 있을경우 /etc/issue.net 파일 설정 고려하지 않아도 됨" >> $CREATE_FILE 2>&1
echo "로그온 시 경고 메시지 제공 TIP"																	>> $CREATE_FILE 2>&1
echo "경고메세지 설정은 다음과 같은 파일에서 처리함"	     														>> $CREATE_FILE 2>&1
echo "issue.net = 사용자가 로그인전에 출력되는 메세지[ssh는 별도설정필요함]"						                                          >> $CREATE_FILE 2>&1
echo "motd = 사용자가 로그인후에 출력되는메세지 "             														>> $CREATE_FILE 2>&1
echo "ssh를 사용한다면 /etc/ssh/sshd_config 파일내의  #Banner none  구문의 주석을 제거한후"                                     >> $CREATE_FILE 2>&1
echo "예제]#Banner none 에서 Banner /etc/issue.net 으로 베너 경로를"   												 >> $CREATE_FILE 2>&1 
echo "변경하여야만 ssh로 로그인할시 베너가 출력된다."              															  >> $CREATE_FILE 2>&1 
echo "단 motd 파일은 접속후에 메세지를 출력하기때문에 별도의 설정없이 telnet 및 ssh 모두 메세지가 출력된다."                         >> $CREATE_FILE 2>&1 
echo "기반시설 취약점 분석평가 기준에는 SSH 배너 설정부분은 언급되지 않으므로, 설정되지 않아도 양호 처리하나, 여력이 될 시 권고사항으로 언급."                         >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② [telnet] 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
U_68_flag_stack=0
U_68_flag=2
if [ ! $os_version -eq 1 ]
then
	### telnet ### 
	if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
			telnet_flag1=M
		else
			echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
			telnet_flag1="Disabled"
		fi
	fi
	if [ $telnet_flag1 == M ] 
	then
		echo "● /etc/issue.net 파일 설정:"                                                             >> $CREATE_FILE 2>&1
		echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
		if [ -f /etc/issue.net ]
		then
			if [ `cat /etc/issue.net | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
			then
				cat /etc/issue.net | grep -v "^#" | grep -v "^ *$"                                         >> $CREATE_FILE 2>&1
				echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
				if [ `cat /etc/issue.net | grep -v "^ *$" | wc -c` -le 50 ]
				then
					echo "<> 경고 메시지 내용이 너무 적습니다 확인이 필요합니다"                                             >> $CREATE_FILE 2>&1
					let U_68_flag_stack=U_68_flag_stack+1
				fi
			else
				echo "<> 경고 메시지 설정 내용이 없습니다.(취약)"                                             >> $CREATE_FILE 2>&1
				let U_68_flag_stack=U_68_flag_stack+1
			fi
		else
			echo "<> /etc/issue.net 파일이 없습니다.(M/T)"                                                       >> $CREATE_FILE 2>&1
			U_68_flag=3
		fi
	fi

else 

	cp /dev/null U-69_telnet_process.txt
	if [ `cat solaris_command_list.txt | grep -i 'svcs' | wc -l` -gt 0 ]
	  then
	  svcs -a | grep telnet                                                                 >> U-69_telnet_process.txt
	fi
	if [ `cat solaris_command_list.txt | grep -i 'inetadm' | wc -l` -gt 0 ]
	  then
	  inetadm | grep telnet                                                                 >> U-69_telnet_process.txt
	fi
	ps -ef | grep telnet | grep -v grep                                                     >> U-69_telnet_process.txt

	echo "③ telnet 관련 설정 "                                                                                 >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1

	if [ `cat U-69_telnet_process.txt | grep telnet | grep -v grep | wc -l` -gt 0 ]; then
	    echo "☞ Telnet Service Enable"                                                                          >> $CREATE_FILE 2>&1
	    echo " "                                                                                                >> $CREATE_FILE 2>&1
	    echo "■ TELNET 배너"                                                                                    >> $CREATE_FILE 2>&1
	    if [ -f /etc/default/telnetd ]; then
	        if [ `cat /etc/default/telnetd | grep -i "banner" | grep -v "^#" | wc -l` -eq 0 ]; then
	        	let U_68_flag_stack=U_68_flag_stack+1
	            echo "/etc/default/telnetd 파일 설정 없음"                                                      >> $CREATE_FILE 2>&1
	          else
	            echo "/etc/default/telnetd 파일 내용"                                                           >> $CREATE_FILE 2>&1
	            cat /etc/default/telnetd | grep -i "banner" | grep -v "^#"                                      >> $CREATE_FILE 2>&1
	        fi
	      else
	        U_68_flag=2
	        echo "/etc/default/telnetd 파일 존재하지 않음"                                                      >> $CREATE_FILE 2>&1
	    fi
	  else
	    echo "☞ Telnet 서비스 비 실행중"                                                                       >> $CREATE_FILE 2>&1
	fi

	echo " "                                                                                                    >> $CREATE_FILE 2>&1

fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/motd 파일 설정: "                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/motd ]
then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/motd | grep -v "^ *$"                                                             >> $CREATE_FILE 2>&1
		echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
		if [ `cat /etc/motd | grep -v "^ *$" | wc -c` -le 50 ]
		then
			echo "<> 경고 메시지 내용이 너무 적습니다 확인이 필요합니다(취약)"                                             >> $CREATE_FILE 2>&1
			let U_68_flag_stack=U_68_flag_stack+1
		fi
	else
		echo "<> 경고 메시지 설정 내용이 없습니다.(취약)"                                             >> $CREATE_FILE 2>&1
		let U_68_flag_stack=U_68_flag_stack+1
	fi
else
	echo "<> /etc/motd 파일이 없습니다.(취약)"                                                            >> $CREATE_FILE 2>&1
	let U_68_flag_stack=U_68_flag_stack+1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/issue 파일 설정: "                                                           >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
then
	if [ `cat /etc/issue | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/issue | grep -v "^#" | grep -v "^ *$"                                         >> $CREATE_FILE 2>&1
		echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다.(취약)"                                             >> $CREATE_FILE 2>&1
		let U_68_flag_stack=U_68_flag_stack+1
	fi
else
	echo "/etc/issue 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $sshd_flag -eq 1 ]
then
	echo "● /etc/ssh/sshd_config 파일 설정"                                                      >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
	cat /etc/ssh/sshd_config | grep -i "Banner" | grep -v "#" 					                  >> $CREATE_FILE 2>&1
	if [ `cat /etc/ssh/sshd_config | grep -i "Banner" | grep -v "#" | awk -F" " ' {print $2}' | egrep '/etc/issue' | wc -l` -eq 0 ]
	then
		echo "<> Banner 설정이 누락되어 있습니다. (취약)"                                                            >> $CREATE_FILE 2>&1
		echo "issue.net 을 설정해야합니다 "                                                 >> $CREATE_FILE 2>&1
		let U_68_flag_stack=U_68_flag_stack+1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	fi 
fi 
rm -f U-69_telnet_process.txt

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $U_68_flag_stack -gt 0 ] 

then
	echo [결과] N                                                                     >> $CREATE_FILE 2>&1
else
	echo [결과] ${FLAG_TABLE[$U_68_flag]}                                                                     >> $CREATE_FILE 2>&1
fi 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-68 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_69() {
echo "[U-69 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.33 NFS 설정 파일 접근 권한 #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.33 NFS 설정 파일 접근 권한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: NFS 접근제어 설정 파일의 소유자가 root 이고, /etc/exports 파일의 권한이 644 이하인 경우 양호 (LINUX)"   >> $CREATE_FILE 2>&1
echo "■ 기준2: NFS 접근제어 설정 파일의 소유자가 root 이고, /etc/dfs/dfstab 파일의 권한이 644 이하인 경우 양호 (SOLARIS)"   >> $CREATE_FILE 2>&1
echo "■       : (/etc/exports 파일 없으면 NFS서비스 이용이 불가능함으로 양호)"                 >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
U_69_flag=0

if [ ! $os_version -eq 1 ]
then
	if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
		then
			ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
		else
			echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
			U_69_flag=2
	fi
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "② /etc/exports 파일 권한 설정"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/exports ]
		then
		ls -alL /etc/exports                                                                        >> $CREATE_FILE 2>&1
		if [ `ls -alL /etc/exports | awk -F" " '{print $1'} | grep '\-..-.--.--' | wc -l` -eq 0 ]
		then
			echo "Permission not satisfied (취약)"                                                  >> $CREATE_FILE 2>&1	
			U_69_flag=1
		else
			U_69_flag=2
		fi
	else
		echo "/etc/exports 파일이 없습니다.(양호)"                                                  >> $CREATE_FILE 2>&1
		U_69_flag=2
	fi

	echo [결과] ${FLAG_TABLE[$U_69_flag]}          	                                                                 >> $CREATE_FILE 2>&1
else # solaris

    
    echo "① NFS 접근통제 파일 설정 "                                                                           >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"                       >> $CREATE_FILE 2>&1
    
    if [ `cat U-24_check_NFS.txt | grep "취약" | wc -l` -gt 0 ]
    then
    
    if [ -f /etc/dfs/sharetab ]
         then
          ls -alL /etc/dfs/sharetab                                                                             >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          if [ ! `ls -alL /etc/dfs/sharetab |  awk '{print $1}' | grep '.....--.--'| wc -l` -eq 1 ]
          then
            let U_69_flag=U_69_flag+1
          fi
    else
          echo " /etc/dfs/sharetab 파일이 없습니다"                                                             >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
    fi
    if [ -f /etc/dfs/dfstab ]
         then
          ls -alL /etc/dfs/dfstab                                                                               >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          if [ ! `ls -alL /etc/dfs/dfstab |  awk '{print $1}' | grep '.....--.--'| wc -l` -eq 1 ]
          then
            let U_69_flag=U_69_flag+1
          fi
     else
          echo " /etc/dfs/dfstab 파일이 없습니다"                                                               >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
     fi
     if [ -f /etc/exports ]
         then
          ls -alL /etc/exports                                                                                  >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
          if [ ! `ls -alL /etc/exports |  awk '{print $1}' | grep '.....--.--'| wc -l` -eq 1 ]
          then
          	let U_69_flag=U_69_flag+1
          fi
      else
          echo " /etc/exports 파일이 없습니다"                                                                  >> $CREATE_FILE 2>&1
          echo " "                                                                                              >> $CREATE_FILE 2>&1
      fi    
    
    else
      echo "NFS Serivce Disable"                                                                      >> $CREATE_FILE 2>&1
      
    fi

    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    
	if [ $U_69_flag -gt 0 ]
	then
		echo [결과] N				                                                                   >> $CREATE_FILE 2>&1
	else
		echo [결과] Y				                                                                   >> $CREATE_FILE 2>&1
	fi     
    
    rm -rf U-24_check_NFS.txt
fi 

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-69 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_70(){ 

echo "[U-70 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.34 expn, vrfy 명령어 제한 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.34 expn, vrfy 명령어 제한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"     >> $CREATE_FILE 2>&1
echo "		: PricacyOptions=authwarnings, goaway(noexpn,novrfy)를 포함하고 있을경우 양호"     >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $CREATE_FILE 2>&1
#CentOS 6.0 이상이 postfix를 사용한다 
flag1="Null"
flag2="Null"

echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	flag1="Enabled"
	ps -ef | grep sendmail | grep -v grep														>> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
	flag1="Disabled"
fi
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ $flag1 == "Enabled" ]
then
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	for configfile in "/etc/sendmail.cf" "/etc/mail/sendmail.cf"
	do
		if [ -f $configfile ]
		  then
		  	flag3=1
  			echo "② $설정 파일의 옵션 확인"                                                    >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
		    grep -v '^ *#' $configfile | grep PrivacyOptions                                      >> $CREATE_FILE 2>&1
		    if [ `grep -v '^ *#' $configfile | grep PrivacyOptions | grep noexpn | wc -l` -eq 0 -o `grep -v '^ *#' $configfile | grep PrivacyOptions | grep novrfy | wc -l` -eq 0 ]
		    then
		    		echo "옵션 설정 누락입니다. (취약)"                                                    >> $CREATE_FILE 2>&1
					flag2=N    
		    else
		    
		    		flag2=Y
		    	
		    fi
		    break
		

		fi
	
	done
	if [ $flag3 == 0 ]
	then
		echo "/etc/sendmail.cf 파일이 없습니다."                                                   >> $CREATE_FILE 2>&1
		flag2="Null"		
	fi 

fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[참고]"                                                                              	   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "/etc/services 파일에서 포트 확인"                                                     	 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ ! $os_version -eq 1 ]
then
	echo "서비스 포트 활성화 여부 확인"                                                        		 >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
		then
			netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		else
			echo "☞ Sendmail Service Disable"                                                         >> $CREATE_FILE 2>&1
		fi
	else
		echo "서비스 포트 확인 불가" 				                                                         >> $CREATE_FILE 2>&1
	fi
		echo " "                                                                                       >> $CREATE_FILE 2>&1
else 
    
    if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
      then
        echo "Sendmail 서비스가 비실행중입니다."                                                                >> $CREATE_FILE 2>&1
      else
        ps -ef | grep sendmail | grep -v "grep"                                                                 >> $CREATE_FILE 2>&1
    fi
fi 
if [ $flag1 == "Disabled" ]
then
	echo [결과] Y >> $CREATE_FILE 2>&1
else
	echo [결과] "$flag2" >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-70 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


}

U_71() {
echo "[U-71 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.35 Apache 웹서비스 정보 숨김 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.35 Apache 웹서비스 정보 숨김           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ServerTokens 지시자로 헤더에 전송되는 정보를 설정할 수 있음.(ServerTokens Prod 설정인 경우 양호)" >> $CREATE_FILE 2>&1
echo "■       : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨."  >> $CREATE_FILE 2>&1
echo "Apache 웹서비스 정보 숨김 TIP"											>> $CREATE_FILE 2>&1
echo "ServerTokens Prod 행을 추가해야함 "									>> $CREATE_FILE 2>&1
echo "ServerTokens Optisns 설명"                                            >> $CREATE_FILE 2>&1 
echo "Prod : 웹서버 종류  - Server:Apache"                                   >> $CREATE_FILE 2>&1 
echo "Min : Prod + 웹서버 버전 - Server:Apache/1.3.0"                         >> $CREATE_FILE 2>&1 
echo "OS : MIN + 운영체제  - Server:Apache/1.3.0(UNIX)"                      >> $CREATE_FILE 2>&1                                                   >> $CREATE_FILE 2>&1 
echo "Full: OS + 설치된 모듈정보 - Server:Apache/1.3.0(UNX)"                  >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_71_flag=0
#REDHAT
if [ `ps -ef | grep "httpd" | grep -v lighttpd | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ `cat $ACONF | grep -i "ServerTokens" | grep -v '\#' | wc -l` -gt 0 ]
	then
		servertoken=`cat $ACONF | grep -i "ServerTokens" | grep -v '\#'`
		echo $servertoken                                          >> $CREATE_FILE 2>&1

		if [ `echo $servertoken | grep "Prod" | wc -l` -eq 0 ]
		then
			echo "Server Tokens 설정이 Prod가 아닙니다"                     >> $CREATE_FILE 2>&1
			U_71_flag=1
		else
			U_71_flag=2
		fi 
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "ServerTokens 지시자가 설정되어 있지 않습니다.(취약)"                                 >> $CREATE_FILE 2>&1
		U_71_flag=1
		
	fi

fi


if [ $U_71_flag == 1 ]
then
	echo [결과] N                                                                                   >> $CREATE_FILE 2>&1

elif [ $U_71_flag == 2 ]
then
	echo [결과] Y                                                                                   >> $CREATE_FILE 2>&1
elif [ $U_71_flag == 0 ] 
	then
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
	echo [결과] Y                                                                                   >> $CREATE_FILE 2>&1
else 
	echo [결과] M                                                                                   >> $CREATE_FILE 2>&1
fi 


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-71 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
}

U_42() {
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################      4. 패치 관리      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "[U-42 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 4.1 최신 보안패치 및 벤더 권고사항 적용 ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     4.1 최신 보안패치 및 벤더 권고사항 적용      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo "☞ uname -a"                                    	                                  	   >> $CREATE_FILE 2>&1
uname -a 																						>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ ! $os_version -eq 1 ]
then
	echo "☞ lsb_release -a"                                    	                                 >> $CREATE_FILE 2>&1
	lsb_release -a 																					 >> $CREATE_FILE 2>&1
	echo "☞ 현재 등록된 서비스"                                                                   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	rpm -qa 2>/dev/null |sort                                                                                  >> $CREATE_FILE 2>&1
	echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo "☞ 현재 보안관련 패치 업데이트 리스트 여부 확인 "                                                                   >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	yum updateinfo list security all                                                                   >> $CREATE_FILE 2>&1

else # solaris

	showrev -p                                                                                                  >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
    pkg info kernel                                                                                             >> $CREATE_FILE 2>&1
    echo " "                                                                                                    >> $CREATE_FILE 2>&1
fi 
echo [결과] M                                                                            >> $CREATE_FILE 2>&1
echo "[U-42 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}
U_43() {

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################      5. 로그 관리      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "[U-43 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.1 로그의 정기적 검토 및 보고 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          5.1 로그의 정기적 검토 및 보고          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고가 이루어지고 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 담당자 인터뷰 및 증적확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "① 일정 주기로 로그를 점검하고 있는가?"                                                  >> $CREATE_FILE 2>&1
echo "② 로그 점검결과에 따른 결과보고서가 존재하는가?"                                        >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
	echo [결과] M                                                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[U-43 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

U_72() {
echo "[U-72 Start]"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.2 정책에 따른 시스템 로깅 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         5.2 정책에 따른 시스템 로깅 설정         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: syslog 에 중요 로그 정보에 대한 설정이 되어 있을 경우 양호"                      >> $CREATE_FILE 2>&1
echo "■ REPORT"                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
U_71_flag=0
echo "① SYSLOG 데몬 동작 확인"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep 'syslog' | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "☞ SYSLOG Service Disable"                                                             >> $CREATE_FILE 2>&1
else
	ps -ef | grep 'syslog' | grep -v 'grep'                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② SYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	if [ `cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/syslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/syslog.conf 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
	let U_71_flag=U_71_flag+1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ RSYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/rsyslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/rsyslog.conf 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
	let U_71_flag=U_71_flag+1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $U_71_flag -gt 1 ] 
then
	echo [결과] N                                                                            >> $CREATE_FILE 2>&1
else

	echo [결과] M                                                                            >> $CREATE_FILE 2>&1
fi 
echo "[U-72 End]"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

}

# ---------------------------------------- MAIN PROCESS ------------------------------------------------
# [주요 정보통신기반시설 기술적 취약점 분석 항목 - 72 개 ]
# #1. 계정관리
U_01
U_02
U_03
U_04
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
# #2. 파일 및 디렉터리 관리
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
U_16
U_17
U_18
U_55
U_56
U_57
U_58
U_59
# #3. 서비스 관리
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_60
U_61
U_62
U_63
U_64
U_65
U_66
U_67
U_68
U_69
U_70
U_71
#4. 패치관리
U_42
U_43
#5. 로그관리
U_72
# ---------------------------------------- MAIN PROCESS END ------------------------------------------------



rm -f proftpd.txt
rm -f vsftpd.txt
rm -f check.txt
rm -f ftpusers.txt
rm -f solaris_command_list.txt
rm -f sshd_ps_ef.txt
echo "***************************************** for copy start *****************************************" >> $CREATE_FILE 2>&1
#결과 붙이기용
cat $CREATE_FILE | grep "Result=" | awk -F"=" '{print $2}' >> $CREATE_FILE 2>&1

echo "***************************************** for copy end *****************************************" >> $CREATE_FILE 2>&1
echo "***************************************** END *****************************************" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo "***************************************** END *****************************************"

echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"


# U-25 NFS 미구동시 진단결과를 양호 -> N/A로 변경
# linux ls -alL == solaris ls -alF
# rlogin 설치방법 : #pkg install pkg://solaris/service/network/legacy-remote-utilities
