#!/bin/bash
#CP Rev 20
#TO DO:
#Go along last year’s rounds

 while true 
 do
 PS3='Please enter your choice: '
 options=("List Programs" "Uninstall Unwanted Programs" "Install Important Programs" "Secure Network" "System Info" "Scan for Malware" "Find Media Files" "System Security" "Update Ubuntu" "Reset PAM" "Clear" "Quit")
 select opt in "${options[@]}" 
 do
     case $opt in
"List Programs")
		sudo dpkg -l >>Program.txt
;;

"Uninstall Unwanted Programs")
             echo "you chose choice 1"

			#torrenting programs
		clear
			echo "Clearing Unwanted Programs"	
			#Remove Torrenting programs
		sudo apt-get purge qbittorrent utorrent ctorrent ktorrent rtorrent deluge transmission-gtk transmission-common tixati frostwise vuze irssi talk telnet

			#Remove pentesting
		sudo apt-get purge wireshark nmap john netcat netcat-openbsd netcat-traditional netcat-ubuntu netcat-minimal

			#cleanup	 
		sudo apt-get autoremove

;;

"Install Important Programs")
             echo "you chose choice 2"
            #install Needed programs
		clear
			echo "Installing anti-virus, anti-malware, firewall, and utilities"
   		sudo apt-get install chkrootkit ufw clamav rkhunter selinux tree auditd bum htop libpam-cracklib symlinks
		clear

;;
        
"Secure Network")
            echo "you chose choice 3"
			#firewall
		clear
			echo "Configuring firewall"
			#block common ports
			#Detail later
  		ufw enable
  		ufw deny 23
 		ufw deny 2049
 		ufw deny 515
  		ufw deny 111
		ufw deny 7100

;;
			 
"System Info")
			#show netstat, ports, sockets, etc.
			echo "LINUX VERSION"
			#shows Linux version
		lsb_release -r
		uname -a
			echo "--------------------------------------------"
			echo "--------------------------------------------"
			echo "FILES IN USE"
			#shows files open in memory
		lsof  -i -n -P
			echo "--------------------------------------------"
			echo "--------------------------------------------"
			echo "SOCKETS IN USE"
			#shows open sockets
		sudo ss -pwult | column -t
			echo "--------------------------------------------"
			echo "--------------------------------------------"
			ECHO "NETSTAT tulpn"
			#same as netstat -anob on Windows
   		netstat -tulpn
   			echo "--------------------------------------------"
			echo "--------------------------------------------"
			echo "VIEW RUNNING DAEMONS"
			#view running services
   		ps -C "$(xlsclients | cut -d' ' -f3 | paste - -s -d ',')" --ppid 2 --pid 2 --deselect -o tty,uid,pid,ppid,args | grep ^?
   			echo "--------------------------------------------"
			echo "--------------------------------------------"
			echo "UNOWNED FILES/PROCESSES"
			echo "If anything comes up below, it tends to be bad"
			#LOL
		ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

;;

"Scan for Malware")
			#Anti-Malware and Anti-Virus Scanning
		clear
			echo "Scanning Now"
			#run anti virus/malware/rootkit/etc
    		sudo chkrootkit
    		sudo freshclam
    		sudo clamscan -r /

;;

"Find Media Files" )
			#media file deletion
		clear
			echo "Find User Files"
			#This writes the locations ox these file types into a text file located in the home directory.			
		find / -name '*.mp3' -type f >>/home/list.txt
		find / -name '*.mov' -type f >>/home/list.txt
    		find / -name '*.mp4' -type f >>/home/list.txt
		find / -name '*.mkv' -type f >>/home/list.txt
		find / -name '*.avi' -type f >>/home/list.txt
    		find / -name '*.mpg' -type f >>/home/list.txtt
    		find / -name '*.mpeg' -type f >>/home/list.txt
		find / -name '*.flac' -type f >>/home/list.txt
		find / -name '*.alac' -type f >>/home/list.txt
		find / -name '*.m4a' -type f  >>/home/list.txt
    		find / -name '*.flv' -type f >>/home/list.txt
    		find / -name '*.ogg' -type f >>/home/list.txt
		find / -name '*.wmv' -type f >>/home/list.txt
		find /home -name '*.gif' -type f >>/home/list.txt
		find /home -name '*.png' -type f >>/home/list.txt
    		find /home -name '*.jpg' -type f >>/home/list.txt
    		find /home -name '*.jpeg' -type f >>/home/list.txt
		find /home -name '*.bmp' -type f >>/home/list.txt
		find /home -name '*.bat' -type f >>/home/list.txt
		find /home -name '*.txt' -type f >>/home/list.txt
		find /home -name '*.pdf' -type f >>/home/list.txt
		find /home -name '*.doc' -type f >>/home/list.txt
		find /home -name '*.docx' -type f >>/home/list.txt
		find /home -name '*.xml' -type f >>/home/list.txt
		find /home -name '*.odt' -type f >>/home/list.txt
		find /home -name '*.torrent' -type f >>/home/list.txt

;;

"System Security")

			#Enable Auditing
		sudo auditctl –e 1 

			#unalias commands
			#makes sure nothing common is macro'd to work against you
		sudo unalias -a
		sudo alias egrep='egrep --color=auto'
		sudo alias fgrep='fgrep --color=auto'
		sudo alias grep='grep --color=auto'
		sudo alias l='ls -CF'
		sudo alias la='ls -A'
		sudo alias ll='ls -alF'
		sudo alias ls='ls --color=auto'
		sudo alias cls='clear'
		sudo alias dir='ls'
		sudo alias type='cat'
		sudo alias apt-get='apt-get'

			#config files
		clear

			#(su)root account
			#change passwords for current user and root account
		sudo passwd root
		sudo passwd -n 1 -x 14 -w 7 root
		sudo passwd $USER
		sudo passwd -n 1 -x 14 -w 7 $USER

		cd /etc
		crontab -e

		sed -i -e 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
		sed -i -e 's/SELINUXTYPE=.*/SELINUXTYPE=mls/' /etc/selinux/config
			#debug
		sudo nano /etc/selinux/config 
		

			#check for malicious sources that may come up when running apt-get
			#ie sync to download... metasploit
    		sudo nano /etc/apt/sources.list

			#make sure if safe, use 8.8.8.8 for name server
    		sudo nano /etc/resolv.conf 		

			#make sure nothing is redirecting
    		sudo nano /etc/hosts 

			#should be empty except for 'exit 0'
			#autorun script
    		sudo nano /etc/rc.local

			#sysctl.conf
		sysctl -w net.ipv4.ip_forward=0
		sysctl -w net.ipv4.conf.all.send_redirects=0 
		sysctl -w net.ipv4.conf.default.send_redirects=0
		sysctl -w net.ipv4.conf.all.accept_source_route=0 
		sysctl -w net.ipv4.conf.default.accept_source_route=0
		sysctl -w net.ipv4.conf.all.accept_redirects=0 
		sysctl -w net.ipv4.conf.default.accept_redirects=0 
		sysctl -w net.ipv4.conf.all.secure_redirects=0 
		sysctl -w net.ipv4.conf.default.secure_redirects=0
		sysctl -w net.ipv4.conf.all.log_martians=1 
		sysctl -w net.ipv4.conf.default.log_martians=1
		sysctl -w net.ipv4.route.flush=1
		sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
		sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
		sysctl -w net.ipv4.conf.all.rp_filter=1 
		sysctl -w net.ipv4.conf.default.rp_filter=1 
		sysctl -w net.ipv4.tcp_syncookies=1
		sysctl -w net.ipv6.conf.all.accept_ra=0 
		sysctl -w net.ipv6.conf.default.accept_ra=0
		sysctl -w net.ipv6.conf.all.accept_redirects=0 
		sysctl -w net.ipv6.conf.default.accept_redirects=0
    		sysctl -p	

    		#lightdm
			echo allow-guest=false >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    		echo autologin-user= >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    		#debug
    		sudo nano /etc/lightdm/lightdm.conf
    		sudo nano /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf		

			#password expiration
		sed -i -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t14/' /etc/login.defs
		sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t0/' /etc/login.defs
		sed -i -e 's/PASS_WARN_DAYS\t[[:digit:]]\+/PASS_WARN_DAYS\t7/' /etc/login.defs

			#bash startup	
		sudo nano /etc/profile
		sudo nano /etc/bashrc
		sudo ls -a /etc/profile.d>>~/bashprofile.txt

			#SSH
		if [[ -f /etc/ssh/sshd_config ]] ; then
    		echo "sshd installed Editing sshd_config and ssh_config."
    			sed -i -e 's/PasswordAuthentication.*/ PasswordAuthentication yes/' /etc/ssh/sshd_config
    			sed -i -e 's/UsePrivilegeSeparation.*/UsePrivilegeSeparation yes/' /etc/ssh/sshd_config
    			sed -i -e 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    			sed -i -e 's/PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    			sed -i -e 's/X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    			sed -i -e 's/UsePam.*/UsePAM yes/' /etc/ssh/sshd_config
    			sed -i -e 's/LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
    			sed -i -e 's/MaxAuthTries.*/MaxAuthTries 4' /etc/ssh/sshd_config
    			sed -i -e 's/PermitUserEnvironment.*/PermitUserEnvironment no' /etc/ssh/sshd_config
    			sed -i -e 's/#   ForwardX11.*/#   ForwardX11 no/' /etc/ssh/ssh_config
    			sed -i -e 's/#   Protocol.*/#   Protocol 2/' /etc/ssh/ssh_config
				sed -i -e 's/#   PasswordAuthentication.*/#   PasswordAuthentication yes/' /etc/ssh/ssh_config
				sed -i -e 's/#   PermitLocalCommand.*/#   PermitLocalCommand no/' /etc/ssh/ssh_config
    		else
    		echo "no sshd_config, editing ssh_config"
    			sed -i -e 's/#   ForwardX11.*/#   ForwardX11 no/' /etc/ssh/ssh_config
    			sed -i -e 's/#   Protocol.*/#   Protocol 2/' /etc/ssh/ssh_config
				sed -i -e 's/#   PasswordAuthentication.*/#   PasswordAuthentication yes/' /etc/ssh/ssh_config
				sed -i -e 's/#   PermitLocalCommand.*/#   PermitLocalCommand no/' /etc/ssh/ssh_config
			fi
					# PermitRootLogin no
					#Protocol 2 ONLY
					#X11 Forwarding should be "no"
					#use PAM should be yes
		sudo service ssh restart
		sudo service sshd restart
			#debug ssh sed
		sudo nano /etc/ssh/sshd_config 
		sudo nano /etc/ssh/ssh_config

			#avahi
		if [[ -f /etc/avahi/avahi-daemon.conf ]] ; then
			sudo nano /etc/avahi/avahi-daemon.conf
		fi

			#apache
		if [[ -f /etc/apache2/apache.conf ]] ; then	
			sudo nano /etc/apache2/apache.conf
		fi

			#Samba
		if [[ -f /etc/samba/smb.conf ]] ; then
			sudo nano /etc/samba/smb.conf
		fi
				
			#UAC
		sudo nano /etc/passwd
		sudo nano /etc/sudoers
			#remove non-admins from sudo and admin group
		sudo nano /etc/group 
			# only those in group sudo can sudo ADMINS ONLY
		sudo tree -a -h -A /etc/sudoers.d>>~/Sudoersdirectory.txt 

			#telnet stuff	
		if [[ -f /etc/xinetd.d/telnet ]] ; then
			sudo nano /etc/xinetd.d/telnet
		fi
		if [[ -f /etc/xinetd.d/wu-ftpd ]] ; then
			sudo nano /etc/xinetd.d/wu-ftpd
		fi
			#To disable ftp, edit the file /etc/xinetd.d/wu-ftpd, and set the field labeled disable to yes.
		if [[ -f /etc/xinetd.d/gssftp ]] ; then
  			sudo nano etc/xinetd.d/gssftp
  		fi	
  			#make disable = yes
  		if [[ -f /etc/init/vsftpd.conf ]] ; then
  		sudo nano /etc/init/vsftpd.conf
  		fi

  		cd /etc/rc.d/init.d
  		./xinted reload
  			#^^ Reloads all this garbage
			#Finally, verify that the xinetd reloaded properly by looking at the output of the system log file using the following command.
  		sudo nano -200 /var/log/messages
  		cd /

  			#part of crontabs
  		sudo nano /etc/pam.d/cron
  			echo "--------------cron.* Directories------------------">>~/cron.txt
  		sudo tree -a -h -A /etc/cron.hourly>>~/cron.txt
  		sudo tree -a -h -A /etc/cron.daily>>~/cron.txt
  		sudo tree -a -h -A /etc/cron.weekly>>~/cron.txt
  		sudo tree -a -h -A /etc/cron.monthly>>~/cron.txt
  		sudo nano /etc/anacrontab
  		sudo nano /etc/crontab
  		sudo nano /etc/hosts.allow
  		sudo nano /etc/hosts.deny

  			#Startup
  			echo "-------------STARTUP-----------">>~/cron.txt
  		sudo tree -a -h -A /var/spool>>~/cron.txt
  		sudo tree -a -h -A /var/spool/cron >>~/cron.txt
  		sudo tree -a -h -A /etc/init>>~/cron.txt

  			#bash motds
  		sudo nano /etc/motd
  		sudo nano /etc/issue
  		sudo nano /etc/issue.net
  			# "remove any instances of \m, \r, \s, or \v." 

  			#rsync, file cync, disable
  		sudo nano /etc/default/rsync

  			#Log File
  			echo "type System Log in the Ubuntu Search for more Log files"
  		sudo nano /var/log/audit/audit.log
  		sudo nano /etc/syslog-ng/syslog-ng.conf

  			#PAM files
  			#pam-cracklib
		sudo nano /etc/pam.d/common-auth 
		sudo nano /etc/pam.conf
		if dpkg -l | grep 'libpam-cracklib' ; then
    		sudo sed -i -e 's/difok=3\+/difok=3 ucredit=-l lcredit=-l dcredit=-l ocreditu=-l' /etc/pam.d/common-password
    	else
    		echo "Someone never installed libpam-cracklib. Doing so now"
    		sudo apt-get install libpam-cracklib
    		sudo sed -i -e 's/difok=3\+/difok=3 ucredit=-l lcredit=-l dcredit=-l ocreditu=-l' /etc/pam.d/common-password
		fi
				# deny=5 unlock_time=1800 to the end of the line with pam_tally2.so
				# minlen=14 - password must be 14 characters or more 
				# dcredit=-1 - provide at least one digit 
				# ucredit=-1 - provide at least one uppercase character 
				# ocredit=-1 - provide at least one special character 
				# lcredit=-1 - provide at least one lowercase character

			#debug since sed is shaky on PAM
		sudo nano /etc/pam.d/common-password	

			#Bootup Services
		sudo bum

;;

"Update Ubuntu")
			echo "Updating Core Linux Dependencies"
    	apt-get update
    	apt-get dist-upgrade

;;

"Reset PAM")
			echo "resetting PAM because SOMEONE decided to mess up."
		sudo pam-auth-update

;;

"Clear")
		clear

;;

"Quit")
             echo "Thank You..."                 
        exit

;;


*) 

			echo Invalid Option. Select something useful or leave.

;;

esac
done
done

 #Checklist
 #open firefox, type in localhost. No connection should occur.
	#If connection happens
		#cd /var/www/
		#check files inside for different server types
