# Get-remote-smb-shell

Hey, everyone！ 
  I'm a novice to ruby and a fan of security penetration testing and open source. By the way, the operating system I use is the latest version of Kali Linux, the desktop window management is awesome, and the terminal is urxvt. They are all great software
  I spent a few days writing this simple windows Samba server brute force cracking and utilization program

Simple functions of program:

## 0x1 ##
scan the target port 445 of the windows system. If it is open, start trying to load the user name and password dictionary for brute force cracking

## 0x2 ##
if the crack is successful, it will try to execute the remote command.

## 0x3 ##
there are four ways to execute commands:
0, execute the remote CMD command (All of this can be customized in the source file)
1. Execute nc.exe (bind shell)
2. Execute MSF bind shell
3. Execute MSF reverse shell

If the above command is executed successfully, you can get the remote command output result or shell or MSF meterpreter

## 0x4 ##
Environmental dependency:
sudo gem install ruby_smb open-uri http

Target dependency:
1. The remote system needs to enable admin$ sharing.
2. The target did not turn on the firewall (Windows 7 / windows 10 passed the test)

## 0x5 ##
Description warning：
All programs and codes are only used for testing and learning
Any comments or suggestions are welcome ..

