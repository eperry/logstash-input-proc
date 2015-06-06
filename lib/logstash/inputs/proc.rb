# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname

# Generate a repeating message.
#
# This plugin is intented only as an example.

class LogStash::Inputs::Proc < LogStash::Inputs::Base
  config_name "proc"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain" 

  # The message string to use in the event.
  #config :message, :validate => :string, :default => "Hello World!"

  # Set how frequently messages should be sent.
  #
  # The default, `60`, means send a message every 60 second.
  config :interval, :validate => :number, :default => 60

  public
  def register
    @host = Socket.gethostname
      @logger.info("Registering Proc Input", :type => @type, :interval => @interval)
  end # def register

def readVmStats(queue)
  file = Pathname.new("/proc/vmstat")
  lines = file.readlines
  lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = /(\w+)\s+([\.\d]+)/.match(line)
      if (m && m.length >= 3 )
      event = LogStash::Event.new("raw"=>line, m[1] => m[2], "file" => file.to_s,"host" => @host, "type" => "vmstats" )
              decorate(event)
              queue << event
      end
  }
end

def readLoadAverage(queue)
  file = Pathname.new("/proc/loadavg")
  lines = file.readlines
  lines.each { |line|
      m = /([\d\.]+)\s+([\d\.]+)\s+([\d\.])+\s+(\d+)\/(\d+)\s+(\d+)/.match(line)
      if (m && m.length >=6 )
      event = LogStash::Event.new("raw"=>  m[0],"1minute" => m[1], "5minute" => m[2], "15minute" => m[3],  "runnable" => m[4], "existing" => m[5],"lastcreatedpid" => m[6], "file" => file.to_s,"host" => @host, "type" => "loadavg" )
              decorate(event)
              queue << event
      end
  }
end
def readMemInfo(queue)
  file = Pathname.new("/proc/meminfo")
  lines = file.readlines

  lines.each { |line|
      m = /(\w+):\s+(\d+)/.match(line)
      if (m && m.length >=3 )
      event = LogStash::Event.new("raw"=>  m[0], m[1] => m[2], "file" => file.to_s,"host" => @host, "type" => "meminfo" )
              decorate(event)
              queue << event
      #else
      #       puts("#"+m.to_s)
      end
    
    
  }
end

def readPidStats(queue)
  @logger.info? && @logger.info("in ReadPidStats ")
  process = Hash.new
  #Loosely based on the GEM ProcTable  which was  based on the Perl Module ProcTable
     Dir.foreach("/proc"){ |file|
        next if file =~ /\D/ # Skip non-numeric directories
        
        # Get /proc/<pid>/cmdline information. Strip out embedded nulls.
        begin
          data = IO.read("/proc/#{file}/cmdline").tr("\000", ' ').strip
          process["cmdline"] = data 
        rescue
          next # Process terminated, on to the next process
        end

        # Get /proc/<pid>/cwd information
        process["cwd"] = File.readlink("/proc/#{file}/cwd") rescue nil

        # Get /proc/<pid>/environ information. Environment information
        # is represented as a Hash, with the environment variable as the
        # key and its value as the hash value.
        process["environ"] = Hash.new

        begin
          IO.read("/proc/#{file}/environ").split("\0").each{ |str|
            key, value = str.split('=')
            process["environ"][key] = value
          }
        rescue Errno::EACCES, Errno::ESRCH, Errno::ENOENT
          # Ignore and move on.
        end

        # Get /proc/<pid>/exe information
        process["exe"] = File.readlink("/proc/#{file}/exe") rescue nil

        # Get /proc/<pid>/fd information. File descriptor information
        # is represented as a Hash, with the fd as the key, and its
        # symlink as the value.
        process["fd"] = Hash.new

        begin
          Dir.foreach("/proc/#{file}/fd/") { |fd|
            process["fd"][fd] = File.readlink("/proc/#{file}/fd/"+fd)  rescue nil
          }
          rescue 
          process["fd"] = ""
          #  # Ignore and move on
        end

        # Get /proc/<pid>/root information
        process["root"] = File.readlink("/proc/#{file}/root") rescue nil

        # Get /proc/<pid>/stat information
        stat = IO.read("/proc/#{file}/stat") rescue next

        # Get number of LWP, one directory for each in /proc/<pid>/task/
        # Every process has at least one thread, so if we fail to read the task directory, set nlwp to 1.
        process["nlwp"] = Dir.glob("/proc/#{file}/task/*").length rescue process["nlwp"] = 1

        # Deal with spaces in comm name. Courtesy of Ara Howard.
        re = %r/\([^\)]+\)/
        comm = stat[re]
        comm.tr!(' ', '-')
        stat[re] = comm

        stat = stat.split

        process["pid"]         = stat[0].to_i
        process["comm"]        = stat[1].tr('()','') # Remove parens
        process["state"]       = stat[2]
        process["ppid"]        = stat[3].to_i
        process["pgrp"]        = stat[4].to_i
        process["session"]     = stat[5].to_i
        process["tty_nr"]      = stat[6].to_i
        process["tpgid"]       = stat[7].to_i
        process["flags"]       = stat[8].to_i
        process["minflt"]      = stat[9].to_i
        process["cminflt"]     = stat[10].to_i
        process["majflt"]      = stat[11].to_i
        process["cmajflt"]     = stat[12].to_i
        process["utime"]       = stat[13].to_i
        process["stime"]       = stat[14].to_i
        process["cutime"]      = stat[15].to_i
        process["cstime"]      = stat[16].to_i
        process["priority"]    = stat[17].to_i
        process["nice"]        = stat[18].to_i
        # Skip 19
        process["itrealvalue"] = stat[20].to_i
        process["starttime"]   = stat[21].to_i
        process["vsize"]       = stat[22].to_i
        process["rss"]         = stat[23].to_i
        process["rlim"]        = stat[24].to_i
        process["startcode"]   = stat[25].to_i
        process["endcode"]     = stat[26].to_i
        process["startstack"]  = stat[27].to_i
        process["kstkesp"]     = stat[28].to_i
        process["kstkeip"]     = stat[29].to_i
        process["signal"]      = stat[30].to_i
        process["blocked"]     = stat[31].to_i
        process["sigignore"]   = stat[32].to_i
        process["sigcatch"]    = stat[33].to_i
        process["wchan"]       = stat[34].to_i
        process["nswap"]       = stat[35].to_i
        process["cnswap"]      = stat[36].to_i
        process["exit_signal"] = stat[37].to_i
        process["processor"]   = stat[38].to_i
        process["rt_priority"] = stat[39].to_i
        process["policy"]      = stat[40].to_i

        # Get /proc/<pid>/status information (name, uid, euid, gid, egid)
        begin
          IO.foreach("/proc/#{file}/status") do |line|
            case line
              when /Name:\s*?(\w+)/
                process["name"] = $1
              when /Uid:\s*?(\d+)\s*?(\d+)/
                process["uid"]  = $1.to_i
                process["euid"] = $2.to_i
              when /Gid:\s*?(\d+)\s*?(\d+)/
                process["gid"]  = $1.to_i
                process["egid"] = $2.to_i
            end
          end
        rescue Errno::ESRCH, Errno::ENOENT
          next
        end

        # If cmdline is empty use comm instead
        process["cmdline"] = process["comm"] if process["cmdline.empty?"]

        @logger.info? && @logger.info("output  ")
        event = LogStash::Event.new( "file" => "/proc" ,"host" => @host, "type" => "pidstats" , "process" => process);
        decorate(event)
        queue << event

      }


end

  def run(queue)
    loop do
      begin
      start = Time.now
      @logger.info? && @logger.info("Reading VmStats ")
      readVmStats(queue)
      @logger.info? && @logger.info("Reading LoadAverage ")
      readLoadAverage(queue)
      @logger.info? && @logger.info("Reading MemInfo ")
      readMemInfo(queue)
      @logger.info? && @logger.info("Getting list of PID ")
      readPidStats(queue);
  
      duration = Time.now - start
      @logger.info? && @logger.info("Parsing completed", 
                                     :duration => duration,
                                     :interval => @interval )

      # Sleep for the remainder of the interval, or 0 if the duration ran
      # longer than the interval.
      sleeptime = [0, @interval - duration].max
      if sleeptime == 0
        @logger.warn("Parsing longer than the interval. Skipping sleep.",
                     :duration => duration,
                     :interval => @interval)
      else
        sleep(sleeptime)
      end
       rescue => exception
      puts exception.backtrace
      raise exception # always reraise
    end
    end # loop
   
  end # def run

end # class LogStash::Inputs::Example