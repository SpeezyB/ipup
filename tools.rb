#!/usr/bin/ruby
# This Library is used to abstract methods that will be needed

# Define Error Classes
class DisconError < StandardError; end
class PingFailError < StandardError; end
class GetSshFails < StandardError; end
class FindIpError < StandardError; end
class TestError < StandardError; end
class CurlError < StandardError; end
class ParseSshError < StandardError; end
class NoDependFileError < StandardError; end
class ArgvError < StandardError; end

# ----------------------
def display_help(opt)
	pad = 0
	opt.each_key{|key|
		pad = key.size > pad ? key.size : pad
	}
	m0		 	=  12		#		\
	m1			=  11		#			> These are the below margins
	m2			=  4		#		/
	pad 		+= 10
	m3			=  (m0 + pad)						# Margin to the 1st col
	m4			=  (m3 + m1 + m2 + 2)		# Margin to the last col
	%Q(
#{' '.ljust(m0)}#{'Argument'.ljust(pad)}|#{'Default'.center(11)}|   #{'[Options] & data'.ljust(pad)}
#{' '.ljust(m0)}#{'-' * ((pad * 2) + 13)}
#{' '.ljust(m0)}#{'-showall'				.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Displays additional messages in console
#{' '.ljust(m0)}#{'-showopts'				.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Displays all options and current values
#{' '.ljust(m0)}#{'-skip'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[checkinet|curl] Skips the listed section
#{' '.ljust(m0)}#{'-inet_false'			.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Triggers an event to simulate no internet connection
#{' '.ljust(m0)}#{'-speedtest'			.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Run speedtest and exit without an ip update
#{' '.ljust(m0)}#{'-with_speed'			.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Triggers update to include a speedtest
#{' '.ljust(m0)}#{'-log'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Open the log in the default  editor
#{' '.ljust(m4)																																				}[view]           Alias for '-log'
#{' '.ljust(m4)																																				}[info]           Logs only 'info' entries
#{' '.ljust(m4)																																				}[debug]          Logs 'info' and 'debug' entries
#{' '.ljust(m4)																																				}[error]          Logs 'info', 'debug' and error entries
#{' '.ljust(m4)																																				}[reset]          Clears current log and exit without ip update
#{' '.ljust(m4)																																				}[create|touch]   Create a blank log and exit without ip update
#{' '.ljust(m4)																																				}[cleandebug]     Clears current log and retarts with debuging turned on
#{' '.ljust(m4)																																				}[report]         Will parse the current log and generate a report
#{' '.ljust(m0)}#{'-timeck'					.ljust(pad)}|#{'5'    .center(m1)}|#{' '.ljust(m2)}[1+]             How many previous minutes to look back in the logs while parsing for ssh fails
#{' '.ljust(m0)}#{'-timewindow'			.ljust(pad)}|#{'30'   .center(m1)}|#{' '.ljust(m2)}[1+]             How many days worth of ssh logs to parse
#{' '.ljust(m0)}#{'-retry_count'		.ljust(pad)}|#{'0'    .center(m1)}|#{' '.ljust(m2)}[0-3]            Only used internally to track recurring runs Do Not Use
#{' '.ljust(m0)}#{'-tail'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Will display the last 10 lines of the current log file

#{' '.ljust(m0)}#{'-edit'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Will launch editor w/ opening core program, tools and log files
#{' '.ljust(m4)																																				}[1+]             Will display the given amount of lines of the current log file
#{' '.ljust(m0)}#{'-test_err'				.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Will throw an exception to test error handling
#{' '.ljust(m0)}#{'-pry'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[checkinet|get_ssh_fails|parse_ssh0|parse_ssh1|get_speed|get_users|api_call|main|main0]
#{' '.ljust(m4)																																				}                 Activate Real time Repl at given breakpoint
#{' '.ljust(m0)}#{'-parse_ssh'			.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            Skips update commands and jumps to parsing ssh
#{' '.ljust(m4)																																				}[exit]           Skips update commands and jumps to parsing ssh and hard exit
#{' '.ljust(m0)}#{'-create_secrets'	.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]
#{' '.ljust(m0)}#{'-update_to_prod'	.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[backup=[Str] copy=[Str] tar=[bool] show=[bool] name=""]
#{' '.ljust(m4)																																				}  [tools|lib|libs]    backup just the tools.rb library
#{' '.ljust(m4)																																				}  [update|core]       backup just the core update ip
#{' '.ljust(m4)																																				}  [all|backup]        backup both the core and tools library
#{' '.ljust(m4)																																				}  [none]              don't backup either file
#{' '.ljust(m4)																																				}--
#{' '.ljust(m4)																																				}  [tools|lib|libs]    copy just the tools.rb library
#{' '.ljust(m4)																																				}  [update|core]       copy just the core update ip
#{' '.ljust(m4)																																				}  [all|all files]     copy both the core and tools library
#{' '.ljust(m4)																																				}  [none]              don't copy either file
#{' '.ljust(m0)}#{'-help'						.ljust(pad)}|#{'false'.center(m1)}|#{' '.ljust(m2)}[nil]            This is what you're reading


)
end

def bool?(str=nil)
	result = case str
						when true, 'true', 'TRUE' 	 then true
						when false, 'false', 'FALSE' then false
					 else
						str
					 end
	result
end

def file_check(filelist)
	pwd = File.absolute_path($0).split('/')[0..-2].join('/') + '/'
	raise 'Invalid File List Format!' if !filelist.is_a?(Hash)
	raise "Unable to perform checks without 'which' command" if !system('which which >/dev/null 2>&1')
	cmds, files = [], []
	results = {}
	result = false

	filelist.each do |k, v|
		if v.split(' ')[0].split('.').size > 1
			files << v.split(' ')[0]
		else
			cmds << v.split(' ')[0]
		end
	end

	cmds.each do |cmd|
		x = %x(which #{cmd} 2>/dev/null).chomp
		raise "Unable to Find the 'which' for #{cmd}" if x.nil?
		files << x	
	end
  cmds.delete_if{|x| x.include?('journalctl')}

	cmds.compact.uniq!
	files.compact.uniq!
	
	files.each do |file|
		if !file.start_with?('/')
			file.prepend(pwd)
		end
		result = if File.exist?(file)
							 true
						 else
							 false
							 #raise "File #{file} not found!!"
						 end
		results.update(file.to_s => result)
	end

	result = true
	results.each do |k,v|
		if !v
			result = !result
		end
	end
	[result, results]
end

def get_fname_bak(rfname)
	origfname = rfname + '.bak'
	if File.exist?(origfname)
		result = origfname + (Dir.glob("#{origfname}*").sort.last[origfname.size..-1].to_i + 1).to_s
	else
		result = origfname
	end
	result
end

def in_place_update(opt={
				backup: 			'none', 
				copy:		 			'all', 
				show: 				false, 
				to_tar: 			true, 
				name: 				'archive_logs_baks.tar',
})
	#require 'minitar'
	#require 'zlib'
	# copy the 2update.rb and 2tools.rb to update.rb & tools.rb
	opt[:show] 		= bool?(opt[:show])
	opt[:to_tar]	=	bool?(opt[:to_tar])
	puts "Upgrading Staging to Production ... "
	dir = File.absolute_path(__FILE__).split('/')[0..-2].join('/') + '/'
	Dir.chdir(dir)
	tar_file_name = opt[:name] || 'archive_logs_baks.tar'
	puts "copy=#{opt[:copy]} // backup=#{opt[:backup]}" if opt[:show]
	pwd = Dir.pwd
	ap opt if opt[:show]
	
	binding.pry if $opts[:pry] == 'update'
	case opt[:backup]
	when 'tools', 'lib', 'libs' # tools.rb.bak<increment number>
		rootfname 	= "#{dir}tools.rb"
		fname 			= get_fname_bak(rootfname) 
		bkexec_str 	= "cp -f #{rootfname} #{fname}"
		p bkexec_str 	if opt[:show]
		puts system(bkexec_str) ? "Backup of 'tools.rb' Complete!" : "Error backup interupted!"
	when 'update', 'core' # updateip.rb.bak<increment number>
		rootfname 	= "#{dir}updateip.rb"
		fname 			= get_fname_bak(rootfname) 
		bkexec_str 	= "cp -f #{rootfname} #{fname}"
		p bkexec_str 	if opt[:show]
		puts system(bkexec_str) ? "Backup of 'updateip.rb' Complete!" : "Error backup interupted!"
	when 'all', 'backup'
		rootfnames 	= ["#{dir}updateip.rb", "#{dir}tools.rb"]
		fnames			= [get_fname_bak(rootfnames[0]), get_fname_bak(rootfnames[1])]
		p fnames 			if opt[:show]
		bkexec_str	=	"cp -f #{rootfnames[0]} #{fnames[0]};cp -f #{rootfnames[1]} #{fnames[1]}"
		p bkexec_str 	if opt[:show]
		puts system(bkexec_str) ? "Backup of 'updateip.rb' & 'tools.rb' Complete!" : "Error backup interupted!"
	else # 'none'
		bkexec_str 	= " "
	end # backup

	if opt[:to_tar]
		to_exclude 	= Dir[tar_file_name, "*.swp", "*updateip.rb", "*updateip.log",
										"*tools.rb", "secrets.yml", File.basename(__FILE__)].uniq.map{|x| './'.concat(x)}.join(' ')
		tar_files		= Dir["./*"].delete_if{|x| to_exclude.include?(x)}.uniq.map!{|x| x[2..-1]}.join(' ')
		tar_str     = if File.exist?(tar_file_name)
										"tar -uf #{tar_file_name} #{tar_files} --remove-files" # --exclude #{to_exclude}
									else
										"tar -cf #{tar_file_name} #{tar_files} --remove-files" # --exclude #{to_exclude}
									end

		p tar_str if opt[:show]
		p tar_files if opt[:show]
		#tarfile = File.open(tar_file_name, 'wb')
		#Minitar.pack(tar_files, tarfile) ? "Tar file #{tar_file_name} has been created" : "Error creating tar file!"
		puts system(tar_str) ? "Tar file #{tar_file_name} has been completed" : "Error creating tar file!"
	end

	puts "Starting Upgrading from Staging to Production..."
	case opt[:copy]
	when 'tools', 'lib', 'libs'
		cpexec_str 	= "cp -f #{dir}2tools.rb #{dir}tools.rb"
		p cpexec_str if opt[:show]
		puts system(cpexec_str) ? "Upgrade from staging to Production Complete!" : "Error Upgrading NOT Completed!"
	when 'update', 'core'
		cpexec_str 	= "cp -f #{dir}2updateip.rb #{dir}updateip.rb"
		p cpexec_str if opt[:show]
		puts system(cpexec_str) ? "Upgrade from staging to Production Complete!" : "Error Upgrading NOT Completed!"
	when 'all', 'all files'
		cpexec_str 	= "cp -f #{dir}2updateip.rb #{dir}updateip.rb;cp -f #{dir}2tools.rb #{dir}tools.rb"
		p cpexec_str if opt[:show]
		puts system(cpexec_str) ? "Upgrade from staging to Production Complete!" : "Error Upgrading NOT Completed!"
	else # 'none'
		cpexec_str = " "
	end # copy

	exit
end

def is_int?(s)
	str = s.to_s
	int_rng = [*0..9].map(&:to_s)			# create an array of ints as strings
	if str != "" || str == nil
		str[0..-1].each_char{|chr|
		if int_rng.include?(chr)
			next
		else
			return false
		end }
		return true
	else
		return nil
	end
end

def contains?(hash, reggie) # only send in regexp into reggie pls 
	result = false
	
	hash.each do |key, val|
		val.each do |val_datum|
			if val_datum.match?(reggie)
				result = !result
				break
			end # end if
		end # val.each to account for arrays as values
	end # hash.each

	result
end

def display_results(stats, type)
	result_string = %Q(
put the stuffs here to put on the screen. And make it pretty.
	)
end

=begin
example of a run
Totals For Current Log File: #{stats[:logfile]}
		# of runs 		| # of unique 		| # of failed attempts		| # of Disconnects		| # of Errors reported
		  						|	ips logged in		|													|											|
		--------------|-----------------|-------------------------|---------------------|---------------------
		
=end
def generate_report(read_log_file, sep="\u00B6", report_type='gen')
#	raise !File.exist?(read_log_file) ? "Unable to generate report from #{read_log_file}" : nil # <<<<<<<<< This needs work ?!?!?!?!?
	require 'awesome_print' if !defined?(awesome_print)
	# require 'time' if !defined?(time)															# <- Maybe needed to compare Times ?!?!?!
	# require 'paint' 																							# Will this be needed?
=begin	
NOTES:
	[x] Need to add a conditional to check for the pid in the log file and only report 1 instance from that record
			rather than all occurances from the run ie: '4 failed ssh attempts' 
		[x] Use the pid and the datetime to determine the amount of runs
	regex: /\[(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d?#\d{3,6} *\])/
	[x] Need to remove the '@' at the front of ips
  [x] remove the '[' and ']' at the front and end of the date with regex
	[x] Filter out any ips that are in the IPWhitelist var
	[ ] implament 'paint' gem ???
	[ ] add the last successful runs returned ip to the IPWhitelist
	[ ] Create differnet reports ['general', 'daily', 'only_errors', 'only_disconnects', 'export_to_CSV']
=end

	stats 					= 	{
		logfile_name:				read_log_file,															# done
		#file:							File.open(stats[:logfile_name], 'r'	),			# done <- is it needed tho?
		records:						[],																					# done
		dates:						{
			date_regex: 			/\[(\d{4}-\d{2}-\d{2})_/, 
			datetime_regex: 	/\[(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2})#/, # YYYY-MM-DD_HH:MM:SS
			data: 						[],	
			total: 						0
		}, # dates:																										# done
		runs:							{
			run_regex: 				/(INFO|DEBUG|ERROR) /, 
			pid_regex:				/#(\d{3,6}) *\]/,
			pid_data:					[],
			#pid_date_regex:		/\[(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}.{3}#\d{3,6}) *\]/,		# Not needed??
			pid_date_buckets:	[],
			total:						0
		}, # runs:																										# done
		ips_logged: 			{
			ip_regex: 				/\b@(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/, 		# The '@' filters out the return of the external ip
			data:							[], 
			total:						0
		}, # ips_logged:																							# done
		failed_attempts:	{
			fail_regex:				/(\d+).failed ssh attempts/i,
			data:							[],
			total:						0
		}, # failed_attempts:																					# done
		disconnects:			{
			discon_regex:			/\#<RuntimeError: Ping Check Failed\./i,
			total:						0
		}, # disconnects:
		errors:						{
			err_regex:				/ERROR/, 
			total:						0
		}	# errors:
	}

	rec = IO.readlines(stats[:logfile_name], sep=sep)
	rec.each do |line|
		lin = line
		if lin.start_with?("\n")
			lin = line.chars.drop(1).join
		end
		if lin.end_with?(sep)
			lin.chomp!(sep)																		# This removes the 'EOR' "\u00B6" == End of record character
		end
		stats[:records] << lin
	end # filling up the records from the file
	stats[:records].delete_if{|i| i == "" || i.nil?}
	stats[:records].compact!
	stats[:records].uniq!

	bucket = {}
	stats[:records].each do |record|			# START of Record Filters Logic ############################

		stats[:dates][:data]							+= record.scan(stats[:dates][:datetime_regex])
		binding.pry if $opts[:pry] == 'rec'
		stats[:ips_logged][:data]					+= record.scan(stats[:ips_logged][:ip_regex])
		stats[:runs][:pid_data]						.push(record.scan(stats[:runs][:pid_regex]))

		tmp_strs 													= [stats[:dates][:data].flatten.last[0..-4], 
													 							stats[:runs][:pid_data].last ].flatten
		bucket_name 											= tmp_strs.join('#').to_sym

		if bucket.has_key?(bucket_name)								#						USE the End of Run Separator = EndOfRun 		= "\u00B7"
			bucket[bucket_name].push(record) 						#add to bucket
		else
			bucket.update(bucket_name => [record])			#next bucket
		end
		
	end 																									# END of Record Filters Logic  ############################
	
	stats[:records]										.clear if $opts[:test] == 'clear'

	stats[:runs][:pid_date_buckets]   = bucket
	stats[:runs][:pid_data]						.flatten!
	stats[:runs][:pid_data]						.compact!
	stats[:runs][:pid_data]						.uniq!
	stats[:runs][:total]							= stats[:runs][:pid_date_buckets].count
	stats[:runs][:pid_data]						.clear if $opts[:test] == 'clear'

	stats[:runs][:pid_date_buckets].each{|bucket_ra|
		binding.pry if $opts[:pry] == 'bucket0'
		if !(bucket_ra[1].join.match(stats[:errors][:err_regex]).nil?)
			stats[:errors][:total] 					+= 1
		end
		if !(bucket_ra[1].join.match(stats[:disconnects][:discon_regex]).nil?)
			stats[:disconnects][:total] 		+= 1
		end
		if !(bucket_ra[1].join.match(stats[:failed_attempts][:fail_regex]).nil?)
			stats[:failed_attempts][:total] += 1
		end
	}

	stats[:runs][:pid_date_buckets].each	

	stats[:dates][:data]							.flatten!
	stats[:dates][:data]							.compact!
	stats[:dates][:data]							.uniq!
	stats[:dates][:total]							= stats[:dates][:data].count
	stats[:dates][:data]							.clear if $opts[:test] == 'clear'

	stats[:ips_logged][:data]					.compact!
	stats[:ips_logged][:data]					.uniq!
	stats[:ips_logged][:data]					.each{|ip| ip.start_with?('@') ? ip.gsub!(/[@]/, '') : nil }	# this removes the '@' in the ip
	stats[:ips_logged][:data]					.delete_if{|i| $IPWhitelist.include?(i)}
	stats[:ips_logged][:total]				= stats[:ips_logged][:data].nil? ? 0 : stats[:ips_logged][:data].uniq.count
	
#	binding.pry
	#display_results(stats, report_type)
	File.open('./testoutfile6.txt', 'w+') {|testie|
		testie.write( stats.ai(plain: true) )
		puts "Report file Generation is Complete."
	}
end

def run_error_tests(raise_err)
	case raise_err
	when 'DisconError'.upcase 					then raise DisconError,				"Running Custom Class Error Test with #{raise_err} !"
	when 'PingFailError'.upcase					then raise PingFailError,			"Running Custom Class Error Test with #{raise_err} !"
	when 'GetSshFails'.upcase						then raise GetSshFails,				"Running Custom Class Error Test with #{raise_err} !"
	when 'FindIpError'.upcase						then raise FindIpError,				"Running Custom Class Error Test with #{raise_err} !"
	when 'TestError'.upcase							then raise TestError,					"Running Custom Class Error Test with #{raise_err} !"
	when 'CurlError'.upcase							then raise CurlError,					"Running Custom Class Error Test with #{raise_err} !"
	when 'ParseSshError'.upcase					then raise ParseSshError,			"Running Custom Class Error Test with #{raise_err} !"
	when 'NoDependFileError'.upcase			then raise NoDependFileError, "Running Custom Class Error Test with #{raise_err} !"
	when 'ArgvError'.upcase							then raise ArgvError, 				"Running Custom Class Error Test with #{raise_err} !"
	end
end
