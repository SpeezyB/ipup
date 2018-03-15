#!/usr/bin/ruby
=begin
	[no] Rather than restarting the script to log output in the event of failure.
			This should be done all during the same run
		[x]	use curl in the mean time	
		[x] add redundancy to ping
	[x]	Base64 encode username / password
		[x] Place in a secrets.yml file for redistrubution
	[x]	Take out the dependancy for 'tail' and use Ruby's file commands
	[x] use speedtest to log the current speed of connection if wanted
	[x] created a 'whitelist' of ips that won't trigger a response
	[x] add user logging as well
		 	[x] use a hash of arrays for the 2D data structure
				the hash is going to be the column names 
				the arrays are going to be the users / this will be easier to get counts and info
				parse the output w/ awk or ruby internal
			[x] use regex to parse the line for the ip addess and put them in the log as well
*		 [?] kick out the user / reboot / change pass
	[x]	Add Support for reading the logs and reporting on failed login attempts
				if it's systemd use -> journalctl -u sshd.service -r | grep -i 'fail'
				if it's not systemd use /var/log/auth.log
	[x] Parse log for only fails that happened in the last 5 mins
		[x]	Add logging for SSH functions
* 	[ ]	add vnc.log to check as well
* [ ]	saving more info in yaml file (encrypt?)
	[x] Either add a 'skip' to getting and setting the ip so to just parse
			or find a way to run '-parse_ssh' and still run the END{} code <- this!
	[x] run a check for required files before starting.
*		[~] abstract relavent methods to another file / module
	[x] refactor the command line args parsing to dectect only -agr data data etc
			until the next '-' else everything is still shovlled into the last arg
*	[ ] Generate a report based of stats in the log files (this and the vnc)
*		[ ] include stats from the vnc log file only if present
	[x] improve the help to show the available options -> maybe in tools.rb?
*	[ ] add benchmarking and if it's too slow run speedtest and start recording inet speeds
	[x] do a lookup of $ARGV and only continue if all $ARGV's are valid else just display help 
	[x] during backup tar all the older logs together
=end
BEGIN{
  require 'logger'
  require 'awesome_print'		# External needs to be installed
	require 'base64'
	require 'yaml'
	require 'date'
	require 'pry'							# External needs to be installed
	require 'resolv'					# Standard Library 

	v 					= '2'
	wd 					= File.absolute_path($0).split('/')[0..-2].join('/') + '/'''
	
	if $0.include?(v)
		require 	"#{wd}2tools.rb"
	else
		require 	"#{wd}tools.rb"
	end
	
	EOR					= "\u00B6"
	EndOfRun 		= "\u00B7"
	Bools				= %w(true false)
#	Ip_Regex		= Resolv::AddressRegex 		# /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
	Ip_Regex		= /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
	Max_tries		= 3
	LogPad			= 25

	Prog_parts	=	{
#		file:				$0.split('/').last,
#		dir:				$0.split('/')[0..-2].join('/') + '/'
		file:			File.basename(__FILE__),
		dir:			File.dirname(File.expand_path(__FILE__)).concat('/'),
	}
	Progfile		=	Prog_parts[:dir] + Prog_parts[:file]
	
	v = Prog_parts[:file].start_with?('2') ? '2' : ''
	Log_parts		= {
#		file:			v + 'updateip.log',
		file:			File.basename(Prog_parts[:file], '.rb').concat('.log'),
		dir:			Prog_parts[:dir].end_with?('/') ? Prog_parts[:dir] : Prog_parts[:dir].concat('/')
#		dir:			'/home/pi/.ipupdate/'
	}

#	if !(File.exist?(Log_parts[:dir] + Log_parts[:file]))
#		Log_parts[:file] = Prog_parts[:file].split('.')[0] + '.log'
#		Log_parts[:dir]	 = Prog_parts[:dir]
#	end
	Logfile			= Log_parts[:dir] + Log_parts[:file]

	Depends_on	= {
		secrets:		'secrets.yml',
		grep: 			'grep',
		vim: 				'vim',
		curl: 			'curl',
		ping: 			'ping',
#		w: 					'w',
		who:				'who',
#		nslookup:		'nslookup', # requires dnsutils package installed or use Resolv standard lib
		users:			'who -q',
		tail:				'tail', 
		journalctl:	'journalctl',
		speedtest:	'speedtest --server 11621'
	}
	fileck_result = file_check(Depends_on)
	raise "A File from Depends_on NOT FOUND!! #{fileck_result}" if fileck_result[0] == false || fileck_result[0] == "false"

	Files 				= {
		auth:				'/var/log/auth.log',
		secrets:		Depends_on[:secrets],
		log:				Logfile,
		prog:				Progfile
	}

	Sites					= {
		dynu:				'api.dynu.com',
		checkip:		{
			dynu:				'checkip.dynu.com',
			ipinfo: 		'ipinfo.io/ip',
			ifconfigme:	'ifconfig.me/ip'
		},
		google: 		'8.8.8.8'
	}

	def create_ip_rng(start_ip, end_ip)
		require 'ipaddr'
		start_ip 	= IPAddr.new(start_ip)
		end_ip		= IPAddr.new(end_ip)

		(start_ip..end_ip).map(&:to_s)
	end

	begin
		local_ips 		= create_ip_rng('192.168.0.2', '192.168.0.225')
		$IPWhitelist 	= (local_ips << %w(0.0.0.0 216.191.105.146)).flatten!
	end
	
	Dir.chdir(Log_parts[:dir])

	$ip = {
		v4: 				'no',
		v6:					'no'
	}

  $opts = {
    showall:				false,
    showopts:				false,
		skip:						false,
		inet_false:			false,
		speedtest:			false,
		with_speed:			false,
    test:						false,		# Not Used ??
		log:						false,
		timeck:					5,				# how many minutes back to check for ssh fails
		timewindow:			30, 			# 1 month in days to grab a pool of data for ssh fails
		retry_count:		0,
		tail:						false,
		edit:						false,
#		resetlog:				false,    # Not Used ??
		test_err:				false,
		pry:						false,
		parse_ssh:			false,
    create_secrets:	false,
		update_to_prod:	false,
		help:						false,
		goodbye:				false,
		pwd:						'',
  }

	if !(ARGV.empty?)
		keys = []
		ARGV.each_with_index do |arg, idx|
			if arg.lstrip.start_with?('-')
				keys << key = arg.chars.drop(1).join.to_sym
				if $opts.has_key?(key)
					$opts[key] 	= !$opts[key]  # create the key and flip the bool
				else
					STDERR.puts "Error! -#{key} is not a valid argument!"
					STDERR.puts "For a list of options you can use, run #{$0} -help"
					exit!(2)
				end
			elsif !keys.last.nil?
				key  				= keys.last
				data 				= if ARGV[idx - 1].start_with?('-')
												arg.downcase
											else
												$opts[keys.last] + arg.downcase.prepend(' ')
											end # data assignment
				$opts[key] 	= data
			else
				raise "Arguments must start with a '-' and then the data!!"
			end # arg.start_with?
		end # ARGV.each
	end # if !ARGV.empty?

	if File.exist?(Files[:secrets])
		$creds = YAML.load_file(Files[:secrets])
	end

	if $opts[:create_secrets] == true
		if File.exist?(Files[:secrets])
			puts "Warning #{Files[:secrets]} already exists!\nOverwrite? "
			confirm = gets.chomp
			if confirm.downcase == 'y'
				puts system("rm #{Files[:secrets]}") ? "#{Files[:secrets]} has been removed" + \
					"\nPlease re-run with \'-create_secrets\' to generate new secrets" : \
					"Error! #{Files[:secrets]} has NOT been removed!"
				goodbye(0)
			else
				puts 'Exitting..'
				exit!(0)
			end
		else
			print 'Enter Hostname of Dynamic DNS: '
			tmp_creds[:host] = gets.chomp
			print '\nEnter Username: '
			tmp_creds[:user] = gets.chomp
			print '\nEnter Password: '
			tmp_creds[:pass] = gets.chomp

			tmp_creds.each{|k, v|	$creds[k] = Base64.encode64(v) }
			File.open(Files[:secrets], 'w+') {|secrets_file|
				secrets_file.write($creds.to_yaml) }
			puts "#{Files[:create_secrets]} has been created."
		end
	
	elsif %w(push export).include?($opts[:create_secrets])
		File.open(Files[:secrets], 'w+') {|secrets_file|
			secrets_file.write($creds.to_yaml) }
		puts "#{Files[:create_secrets]} has been created with exported values"
	end

	case
	when $opts[:help]
		puts display_help($opts)
    exit!(0)
	when $opts[:tail] != false
		if $opts[:tail] == true
			lines = 10
		else
			lines = $opts[:tail]
		end
		if File.exist?(Logfile)
			exec_str = "#{Depends_on[:tail]} #{Logfile} -n #{lines}"
			exec(exec_str)
		else
			puts "#{Logfile} does not exist yet.\nPlease re-run with '-log create' to create log file"
			exit(1)
		end
	when $opts[:edit] != false
		v = if Prog_parts[:file].start_with?('2')
					'2'
				else
					''
				end
		if $opts[:edit] == true
			exec_str = "#{Depends_on[:vim]} #{Progfile} #{Prog_parts[:dir]}#{v}tools.rb #{Logfile}"
		else
			exec_str = "#{Depends_on[:vim]} #{$opts[:edit]} #{Progfile} #{Prog_parts[:dir]}#{v}tools.rb #{Logfile}"
		end
		exec(exec_str)
	end # case

	$Log = Logger.new(Logfile, 'weekly')
  $Log.datetime_format = '%Y-%m-%d %H:%M:%S'

	case $opts[:log]
  when 'info'
    $Log.level = Logger::INFO
  when 'error'
    $Log.level = Logger::ERROR
	when 'debug'
		$Log.level = Logger::DEBUG
	when 'reset'
		File.delete(Logfile) 
		puts "--Current Log File: #{Logfile} has been cleared and reset!!--\n\n"
		exit!(0)
	when 'create', 'touch'
		$Log.level = Logger::INFO
		puts File.exist?(Logfile) ? "#{Logfile} has been created." : "ERROR! #{Logfile} has not been created!"
		exit!(0)
	when 'cleandebug'
		File.delete(Logfile)
		puts "--Current Log File: #{Logfile} has been cleared and reset!!--\n\nStarting with debug turned ON\n\n"
		$Log = Logger.new(Logfile, 'weekly')
		$Log.datetime_format = '%Y-%m-%d %H:%M:%S'
		$Log.level = Logger::DEBUG
	when 'report'
		generate_report(Logfile, EOR)
		exit!(0)
	when true, 'view'
		exec_str = "#{Depends_on[:vim]} #{Logfile}"
		exec(exec_str)
	else
    $Log.level = Logger::INFO
  end

	$Log.formatter = proc do |severity, datetime, progname, msg|
		"#{severity.ljust(5)} [#{datetime.strftime('%Y-%m-%d_%H:%M:%S')}##{Process.pid.to_s.ljust(6)}] #{progname}> #{msg}\n"
	end
	$Log.debug('[Startup]'.ljust(LogPad)) {"Program FileName and path = #{Progfile}#{EOR}"}
	$Log.debug('[Startup]'.ljust(LogPad)) {"The result of File_check.exist? = #{fileck_result.ai(plain: true).to_s}#{EOR}"}

	if !$opts[:update_to_prod] == false
		if $opts[:update_to_prod] == true
			in_place_update		#plain, no backup
		else
			args = $opts[:update_to_prod].split(' ')
			if args[0] == 'backup' && args[1].nil?
				in_place_update(args[0])
			else
				in_place_update(args[0], args[1])
			end
		end
	end

	$opts[:pwd] = File.expand_path(File.dirname(__FILE__))
} # End of Startup Biz

def goodbye(code=0)
	$Log.debug('[Goodbye]'.ljust(LogPad)) {"Goodbye.#{EndOfRun}#{EOR}"} if bool?($opts[:goodbye])
	$Log.close

	exit!(code) if $opts[:log] == 'cleandebug' # Just exit as there will be nothing to parse for errors

	if File.exist?(Logfile)
		if $opts[:retry_count].to_i < Max_tries
			count = $opts[:retry_count].to_i + 1 
			remaining_args = ""

			if !ARGV.nil?
				retry_str = '-retry_count'
				if ARGV.include?(retry_str)
					# this will delete retry then the index will be readjusted and it'll then delete the value <- no longer valid ??
					retry_index = [ARGV.index(retry_str), ARGV.index(retry_str) + 1].reverse
					retry_index.each{|d| ARGV.delete_at(d)} # remove the retry and it's count to avoid nestting
				end
				
				ARGV.each{|arg|
					next_arg = ARGV[ARGV.index(arg) + 1].to_s + ' '
					remaining_args << if arg.to_s.start_with?('-') && (!next_arg.start_with?('-') || \
																next_arg.nil? || next_arg == '')
															arg.to_s.include?('log') ? '' : [arg, next_arg].join(' ')
														elsif arg.to_s.start_with?('-') 
															arg.to_s
														else
															''
														end	}
			end
			remaining_args << ' -log debug'
			exec_str = "#{Progfile} -retry_count #{count} #{remaining_args}"
	#		ap exec_str
			$opts[:log]!='reset' ? IO.readlines(Logfile)[-2..-1].each{|l| l.include?('ERROR') ? exec(exec_str) : nil} : nil
		else
			puts "Too Many retries! Breaking Loop!!"
			exit!(7)
		end
	end

	print ".\n"
	exit!(0)
end

def ping(site)
	%x(#{Depends_on[:ping]} -c 1 -W 1 #{site}).include?("1 received")
end

def checkinet
	return false if $opts[:inet_false] || $opts[:skip] == 'checkinet'
	$opts[:pry] == 'checkinet' ? binding.pry : nil
  begin
		if ping Sites[:dynu]
			return true
		else
			$Log.debug('[checkinet]'.ljust(LogPad)) {"Ping Failed on #{Sites[:dynu]}#{EOR}"}
			if ping Sites[:google]
				return true
			else
				$Log.debug('[checkinet]'.ljust(LogPad)) {"Ping Failed on #{Sites[:google]}#{EOR}"}
			end
		end
  rescue err
		ping_fail = 'Error! Ping Check Failed to #{Sites[:dynu]}. Please check Internet connection and retry!!'
		$Log.error('[checkinet]'.ljust(LogPad)) {"ERROR! #{err.backtrace.ai(plain: true).to_s}#{EOR}"}
		$Log.error('[checkinet]'.ljust(LogPad)) {"ERROR! #{err.inspect}\n#{err.message}\n#{EOR}"}
    $Log.error('[checkinet]'.ljust(LogPad)) {ping_fail + "#{EOR}"}
    raise ping_fail
  end
end

def journalctl?
	result = !%x(#{Depends_on[:journalctl]} -u sshd.service 2>&1).downcase.include?('no journal')
	$Log.debug('[journalctl?]'.ljust(LogPad)) {"Journalctl == #{result.ai(plain: true).to_s}#{EOR}"}
	result
end

def authlog?
	result = File.exists?(Files[:auth])
	$Log.debug('[authlog?]'.ljust(LogPad)) {"Auth.log == #{result.ai(plain: true).to_s}#{EOR}"}
end

def get_ssh_fails(days=$opts[:timewindow])
	binding.pry if $opts[:pry] == 'get_ssh_fails'
	# This checks the system to see how sshd is logged, will grep the log and only take the last 2 months of failed attempts
	if is_int?(days)
		timewindow = 60 * 60 * 24 * days.to_i
	else
		raise "Invalid datatype passed to -timewindow!!!"
	end
	now = Time.now.localtime("-05:00")
	begin
		case
		when journalctl? == true
			fails = %x(#{Depends_on[:journalctl]} -u sshd.service | #{Depends_on[:grep]} -i 'fail')
			$Log.debug('[get_ssh_fails]'.ljust(LogPad)) {"Journalctl Fails == #{fails.to_s.lines.ai(plain: true).to_s}#{EOR}"}
		when authlog? == true
			fails = %x(#{Depends_on[:grep]} -i 'sshd' #{Files[:auth]} | #{Depends_on[:grep]} -i 'fail')
			$Log.debug('[get_ssh_fails]'.ljust(LogPad)) {"Auth.Log Fails == #{fails.to_s.lines.ai(plain: true).to_s}#{EOR}"}
		else
			fails = nil
			$Log.debug('[get_shh_fails]'.ljust(Logpad)) {"SSH Logs not found! fails == nil#{EOR}"}
			raise "Unable to find sshd logs!"
		end
		
		if fails == ""
			parsed = nil
		else
			parsed = fails.each_line.select{|s| 
			s.start_with?(now.strftime('%b'), Time.at(now.to_i - timewindow ).strftime('%b'))}
		end

	rescue => err
		$Log.error('[get_users-rescue]'.ljust(LogPad)) {"ERROR! #{err.backtrace.ai(plain: true).to_s}#{EOR}"}
		$Log.error('[get_users-rescue]'.ljust(LogPad)) {"ERROR! #{err.inspect}#{EOR}"}
		STDERR.puts "Error! -> #{err.message}\n#{err.backtrace}\n#{err.inspect}\n"
	end
	parsed
end

def parse_ssh_logs(minutes=$opts[:timeck])		# Still needs work!!!!
	binding.pry if $opts[:pry] == 'parse_ssh0'
	result = []
	to_parse = get_ssh_fails
	now = Time.now.localtime("-05:00")
	time_window = minutes.to_i * 60 
	binding.pry if $opts[:pry] == 'parse_ssh1'
	
	less_time_window = Time.at(now.to_i - time_window).localtime("-05:00")
	unless to_parse.nil? || to_parse == ""
		to_parse.each.select{|line|
			full_fail_date = line.split(' ')[0..2]
			fail_time = full_fail_date[2].split(':') # produces array of [hh, mm, ss]
			timestamp = Time.new(now.year, full_fail_date[0], full_fail_date[1], 
													fail_time[0], fail_time[1], fail_time[2], "-05:00")
			case timestamp <=> less_time_window
			when 0, 1 then	result << line
			end
		}	
	end

	info = {
		full_data:		result,
		count:				result.select{|x| x.include?('Failed password for ')}.uniq.size,
		parsed:				result.select{|x| x.include?('Failed password for ')}
	}
	
	failed_ips = []
	info[:parsed].each{|x|
		failed_ips << x.match(Ip_Regex).to_s
	}
	info[:failed_ips] = failed_ips.uniq
	$Log.debug('[parse_ssh_logs]'.ljust(LogPad)) {"Info Dump: #{info.ai(plain: true).to_s}#{EOR}"}
	
	str = info[:count] > 0 ? \
		" // #{info[:count]} ssh fails from ip(s): "\
		"#{info[:failed_ips].join(', ')} in the last #{minutes} mins." : \
		" // #{info[:count]} failed ssh attempts in the last #{minutes} mins."
	$Log.debug('[parse_ssh_logs]'.ljust(LogPad)) {"Return String: #{str.ai(plain: true).to_s}#{EOR}"}
	return str
end

def findip
	result = ''
	Sites[:checkip].each do |key, site|
		result = %x(#{Depends_on[:curl]} "#{site}" 2>/dev/null).split(' ').last
		$Log.debug('[findip]'.ljust(LogPad)) {"Using #{site} to resolve IP ... #{EOR}"}
		result.nil? ? \
			$Log.debug('[findip]'.ljust(LogPad)) {"No IP from #{site} #{EOR}"} : \
			break
	end
	if result == "" || result == nil
		raise "ERROR! Unable to get External IP from #{Sites[:ipinfo]}"
	else
		return result
	end
end

def get_speed(just_once=false)
	binding.pry if $opts[:pry] == 'get_speed'
	result = []
	info = %x(#{Depends_on[:speedtest]}).lines
	info.each do |line|
		if line.include?('Download:') || line.include?('Upload:')
			result << line.chomp
		end
	end
	$Log.debug('[get_speed]'.ljust(LogPad)) {"Speed Test Output: #{info.join}#{EOR}"}
	just_once ? info.join : result.join(' ')
end

def get_users
	binding.pry if $opts[:pry] == 'get_users'
	result = []
	content = %x(#{Depends_on[:who]}).lines
	#current_total_users = content[0].match(/[\d{1,2}].user/).to_s.split(' ')[0]
	current_total_users = %x(#{Depends_on[:users]}).lines[1].split('=').last.chomp
	$Log.debug('[get_users]'.ljust(LogPad)) {"Current_total_users: #{current_total_users.ai(plain: true).to_s}#{EOR}"}
	$Log.debug('[get_users]'.ljust(LogPad)) {"Get Users Info: #{content.ai(plain: true).to_s}#{EOR}"}

	content.each{|line|
		linedata = line.split(' ')
		user_ip = [linedata[0]]
		 
		user_ip[1] = 	if linedata[1].include?('tty') || line.include?('(:0)')
										'0.0.0.0'
									else
										if !(line.to_s =~ Ip_Regex).nil?
											line.match(Ip_Regex).to_s
										else
											host = line.match(/\((.*?)\)/).to_s.delete('(').delete(')')
											$Log.debug('[get_users-content.each]'.ljust(LogPad)) {"Hostname of Logged in user : #{host}#{EOR}"}
											Resolv.getaddress(host) # extract the hostname between two ()
										end
										#line.match(Ip_Regex).to_s
								 	end
		result << user_ip
	} # End content.each

	result.map!{|e|	e.join('@')	}
	info = [current_total_users,' // Ip Addresses: ', result.join(', ')].join
	$Log.debug('[get_users]'.ljust(LogPad)) {"Return of get_users -> #{info.ai(plain: true).to_s}#{EOR}"}
	return info
end

def api_call(payload)
	binding.pry if $opts[:pry] == 'api_call'
	result = if %w(curl curls).include?($opts[:skip])
						 "SKIPPED CURL --nochg--" 
					 else
						 %x(#{Depends_on[:curl]} "#{payload}" 2>/dev/null) # 2>&1 <- will give too much, should be 2>/dev/null, just the errors
					 end
	$Log.debug('[api_call]'.ljust(LogPad)) {"Payload: #{payload.ai(plain: true).to_s}#{EOR}"}
	$Log.debug('[api_call]'.ljust(LogPad)) {"Result: #{result.ai(plain: true).to_s}#{EOR}"}
	result
end

begin # Begin Main Program main
	$opts[:pry] == 'main' ? binding.pry : nil
  ap $opts if $opts[:showopts]

	$Log.debug('[main]'.ljust(LogPad)) {"Ruby Ver. #{%x(ruby -v).chomp}#{EOR}"}
  $Log.debug('[main]'.ljust(LogPad)) {"Options = #{$opts.ai(plain: true).to_s}#{EOR}"}

	case
	when  $opts[:parse_ssh] == true 		then ap parse_ssh_logs
	when  $opts[:parse_ssh] == 'exit'
		if !checkinet
			failure = 'Checkinet failed!'
			raise failure
			$Log.error('[main-parse_ssh&exit]'.ljust(LogPad)) {"#{failure}#{EOR}"}
		end
		content = 'Total Users Logged in: ' + get_users + parse_ssh_logs
		$Log.debug('[main-parse_ssh&exit]'.ljust(LogPad)) {"Contents == #{content.ai(plain: true).to_s}#{EOR}"}
		if $opts[:log] == false
			$Log.info('[main-parse_ssh&exit]'.ljust(LogPad)) {"Contents == #{content}#{EndOfRun}#{EOR}"}
		else
			$Log.info('[main-parse_ssh&exit]'.ljust(LogPad)) {"Contents == #{content}#{EOR}"}
		end
		puts content
		goodbye(0)
	when  $opts[:parse_ssh] != false		then ap parse_ssh_logs($opts[:parse_ssh])
	end

	if $opts[:test_err] == true
		raise "Test ERROR!"
	else
		raise $opts[:test_err] if !($opts[:test_err] == false)
	end

	binding.pry if $opts[:pry] == 'main0'
  if !checkinet
		ping_fail = 'Ping Check Failed. Please check Internet Connection and try again!!'
    $Log.error('[main-checkinet]'.ljust(LogPad)) {"#{ping_fail}#{EOR}"}
    raise ping_fail
	else
		$ip[:v4] = findip
  end

	if $opts[:speedtest] == true				# !!!! need to re-think how to acutally use this !!!!
		speed = get_speed('just_once')
		puts "#{speed}"
		goodbye(0)
	end

	pay_load = "http://api.dynu.com/nic/update?hostname=#{Base64.decode64($creds[:host])}" <<
				 		 "&myip=#{$ip[:v4]}&myipv6=#{$ip[:v6]}" <<
				 		 "&username=#{Base64.decode64($creds[:user])}&password=#{Base64.decode64($creds[:pass])}" 

	curl = api_call(pay_load)

	if curl == "" || curl == nil
		$Log.debug('[main]'.ljust(LogPad)) {"Ping to #{Base64.decode64($creds[:host])} DATA: #{ping(Base64.decode64($creds[:host]))}#{EOR}"}
		$Log.debug('[main]'.ljust(LogPad)) {"Payload Dump: #{pay_load.ai(plain: true).to_s}#{EOR}"}
		$Log.debug('[main]'.ljust(LogPad)) {"Curl Dump: #{curl.ai(plain: true).to_s}#{EOR}"}
		raise "ERROR! Payload empty! No Response from Curl !"
	else
		#contents = curl.lines[3..-1].size >= 1 ? curl.lines.last : curl.lines[3..-1].join(" | ")
		contents = 	if curl == "" || curl.nil?
							 		raise "ERROR! Unable to recieve data from #{Depends_on[:curl]} command!"
								else
									curl.strip.lines.size > 1 ? curl.lines.join(" | ") : curl.strip
								end
		contents << " // Total Users Logged in: #{get_users}" 
		contents << parse_ssh_logs
		if $opts[:with_speed]
			if speed != nil
				contents << " // Speedtest: #{speed}"
			else
				contents << " // Speedtest: #{get_speed}"
			end
		end
	end

	$Log.debug('[main]'.ljust(LogPad)) {"Curl DATA : #{curl.inspect}#{EOR}"}
	$Log.debug('[main]'.ljust(LogPad)) {"Curl lines DATA : #{curl.lines.ai(:plain => true).to_s}#{EOR}"}
	if $opts[:log] == false
		$Log.info('[main]'.ljust(LogPad)) {"IP : #{$ip[:v4].ljust(15)} // Contents : #{contents}#{EndOfRun}#{EOR}"}
	else
		$Log.info('[main]'.ljust(LogPad)) {"IP : #{$ip[:v4].ljust(15)} // Contents : #{contents}#{EOR}"}
	end
 
  result = %Q(
Current IP: #{$ip[:v4]}
Result of Update: #{contents}

)

  result << curl if $opts[:showall]

	$Log.debug('[main]'.ljust(LogPad)) {"Result Data : #{result.lines.ai(plain: true).to_s}#{EOR}"}

  puts result
rescue => err
	$Log.error('[main-rescue]'.ljust(LogPad)) {"ERROR! #{err.backtrace.ai(plain: true).to_s}#{EOR}"}
	$Log.error('[main-rescue]'.ljust(LogPad)) {"ERROR! #{err.inspect}#{EOR}"}
	$Log.error('[main-rescue]'.ljust(LogPad)) {"ERROR!#{EOR}"}
	STDERR.puts "Error! -> #{err.message}\n#{err.inspect}\n#{err.backtrace}\n\n"
	goodbye
end

Kernel.at_exit {
	goodbye(0)
}	

