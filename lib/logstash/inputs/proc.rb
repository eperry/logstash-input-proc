# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require 'etc'

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
  config :interval,   :validate => :number, :default => 60
  config :vmstats,    :validate => :hash
  config :loadavg,    :validate => :hash
  config :meminfo,    :validate => :hash
  config :pidstats,   :validate => :hash
  config :diskstats,  :validate => :hash
  config :mounts,     :validate => :hash
  config :netdev,     :validate => :hash
  config :cpuinfo,    :validate => :hash
  config :crypto,     :validate => :hash
  config :wireless,   :validate => :hash
  config :sysipcshm,  :validate => :hash
  
  public
  def register
    @host = Socket.gethostname
    @logger.info("Registering Proc Input", :type => @type, :interval => @interval)
    
  end # def register

def readVmStats(queue)
  file = Pathname.new("/proc/vmstat")
  lines = file.readlines
  vmstats = {}
  lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = /(\w+)\s+([\.\d]+)/.match(line)
      if (m && m.length >= 3 )
        vmstats[m[1]]=m[2].to_i
      end
  }
  event = LogStash::Event.new( 'vmstats'=> vmstats, "file" => file.to_s,"host" => @host, "type" => "vmstats" )
  decorate(event)
  queue << event

end

def readLoadAverage(queue)
  file = Pathname.new("/proc/loadavg")
  lines = file.readlines
  loadavg = {}
  lines.each { |line|
      m = /([\d\.]+)\s+([\d\.]+)\s+([\d\.])+\s+(\d+)\/(\d+)\s+(\d+)/.match(line)
      if (m && m.length >=6 )
        loadavg["1minute"] =  m[1].to_i
        loadavg["10minute"] = m[2].to_i
        loadavg["15minute"] = m[3].to_i
        loadavg["runnable"] = m[4].to_i
        loadavg["existing"] = m[5].to_i
        loadavg["lastcreatedpid"] = m[6].to_i
        event = LogStash::Event.new( "loadavg" => loadavg,   "file" => file.to_s,"host" => @host, "type" => "loadavg" )
        decorate(event)
        queue << event
      end
      
  }
end

def readMemInfo(queue)
  file = Pathname.new("/proc/meminfo")
  lines = file.readlines
  meminfo={}
  lines.each { |line|
      m = /(\w+):\s+(\d+)/.match(line)
      if (m && m.length >=3 )
        meminfo[m[1]] = m[2].to_i
      #else
      #       puts("#"+m.to_s)
      end
  }
  meminfo["CalcMemUsed"]=meminfo["MemTotal"]-meminfo["MemFree"]
  event = LogStash::Event.new("meminfo"=>meminfo, "file" => file.to_s,"host" => @host, "type" => "meminfo" )
              decorate(event)
              queue << event
      
end

def readPidStats(queue)
  @logger.info? && @logger.info("in " + $0)
  fuid = -1
  
  if @pidstats.has_key?("user")
    fuid = Etc.getpwnam(@pidstats["user"]).uid
    @logger.info? && @logger.info("Filtering userid =" + @pidstats["user"] )
  end
  process = Hash.new
  #Loosely based on the GEM ProcTable  which was  based on the Perl Module ProcTable
     Dir.foreach("/proc"){ |file|
        next if file =~ /\D/ # Skip non-numeric directories
        if fuid >= 0
          fileUid = File.stat("/proc/"+file).uid
          next if fileUid != fuid
        end
        
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

        
        event = LogStash::Event.new( "file" => "/proc" ,"host" => @host, "type" => "pidstats" , "process" => process);
        decorate(event)
        queue << event

      }


end
def readDiskStats(queue)
  	# 1 - major number
		# 2 - minor mumber
		# 3 - device name
		# 4 - reads completed successfully
		# 5 - reads merged
		# 6 - sectors read
		# 7 - time spent reading (ms)
		# 8 - writes completed
		# 9 - writes merged
		#10 - sectors written
		#11 - time spent writing (ms)
		#12 - I/Os currently in progress
		#13 - time spent doing I/Os (ms)
		#14 - weighted time spent doing I/Os (ms)
		file = Pathname.new("/proc/diskstats")
    lines = file.readlines
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = line.split(/\s+/)
      if (m && m.length >= 13 )
      event = LogStash::Event.new("raw"=>line, 
              "major"             => m[1].to_i, 
              "minor"             => m[2].to_i,
              "dev"               => m[3],
              "readsCompleted"    => m[4].to_i,
              "readsMerged"       => m[5].to_i,
              "sectorsRead"       => m[6].to_i,
              "readsTimeSpentMS"  => m[7].to_i,
              "writesCompleted"   => m[8].to_i,
              "writesMerged"      => m[9].to_i,
              "sectorsWritten"    => m[10].to_i,
              "writesTimeSpentMS" => m[11].to_i,
              "iosInProgress"     => m[12].to_i,
              "ioTimeSpentMS"     => m[13].to_i,
              "ioWeightedTimeSpentMS" => m[14].to_i,
              "file"              => file.to_s,
              "host"              => @host, 
              "type"              => "diskstats" )
              decorate(event)
              queue << event
      end
  }

end
def readMounts(queue)
    #The 1st column specifies the device that is mounted.
    #The 2nd column reveals the mount point.
    #The 3rd column tells the file-system type.
    #The 4th column tells you if it is mounted read-only (ro) or read-write (rw).
    #The 5th and 6th columns are dummy values
		file = Pathname.new("/proc/mounts")
    lines = file.readlines
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = line.split(/\s+/)
      if (m && m.length >= 6 )
      event = LogStash::Event.new("raw"=>line, 
              "device"            => m[0], 
              "mountpoint"        => m[1],
              "fsType"            => m[2],
              "flagsRaw"          => m[3],
              "flags"             => m[3].split(/\,/),
              "dummy1"            => m[4],
              "dummy2"            => m[5],
              "file"              => file.to_s,
              "host"              => @host, 
              "type"              => "mounts" )
              decorate(event)
              queue << event
      end
  }

end
def readNetDev(queue)
    #  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed

		file = Pathname.new("/proc/net/dev")
    lines = file.readlines
    junk = lines.shift
    junk = lines.shift
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = line.strip.split(/[:\s]+/)
      if (m && m.length >= 17 )
      event = LogStash::Event.new("raw"=>line, 
              "iface"         => m[0], 
              "rxbytes"       => m[1].to_i,
              "rxpackets"     => m[2].to_i,
              "rxerrors"      => m[3].to_i,
              "rxdrops"       => m[4].to_i,
              "rxfifo"        => m[5].to_i,
              "rxframe"       => m[6].to_i,
              "rxcompressed"  => m[7].to_i,
              "rxmulticast"   => m[8].to_i,
              "txbytes"       => m[9].to_i,
              "txpackets"     => m[10].to_i,
              "txerrors"      => m[11].to_i,
              "txdrops"       => m[12].to_i,
              "txfifo"        => m[13].to_i,
              "txframe"       => m[14].to_i,
              "txcompressed"  => m[15].to_i,
              "txmulticast"   => m[16].to_i,
              "file"          => file.to_s,
              "host"          => @host, 
              "type"          => "netdev" )
              decorate(event)
              queue << event
      end
  }

end
def readCpuInfo(queue)
    #  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    cpuinfo = Hash.new
		file = Pathname.new("/proc/cpuinfo")
    lines = file.readlines
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      if ( line.length == 1 )
        event = LogStash::Event.new( 
              "cpuinfo"       => cpuinfo,
              "file"          => file.to_s,
              "host"          => @host, 
              "type"          => "cpuinfo" )
        decorate(event)
        queue << event
        cpuinfo = Hash.new
        next
      end
      m = line.strip.split(/\s+:\s+/)
      if ( m && m.length >= 2 )
        if ( "flags" == m[0] )
          cpuinfo[m[0]] = m[1].strip.split(/\s+/)
          next
        end
        if ( /(processor|cpu MHz|physical id|siblings|core id|cpu cores|apicid|initial apicid|cpuid level|bogomips|clflush size|cache size)/.match(m[0]) )
          cpuinfo[m[0]] = m[1].to_i
          next
        end
        if ( /(cpu MHz|bogomips)/.match(m[0]) )
          cpuinfo[m[0]] = m[1].to_f
          next
        end
        if ( /(cache size)/.match(m[0]) )
          cpuinfo[m[0]] = m[1].split(/\s+/)[0].to_i
          next
        end
        cpuinfo[m[0]] = m[1]
      end
    }
end
def readCrypto(queue)
    #  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    #processor	: 0
    #vendor_id	: GenuineIntel
    #cpu family	: 6
    #model		: 69
    #model name	: Intel(R) Core(TM) i5-4210U CPU @ 1.70GHz
    #stepping	: 1
    #microcode	: 0x17
    #cpu MHz		: 799.996
    #cache size	: 3072 KB
    #physical id	: 0
    #siblings	: 4
    #core id		: 0
    #cpu cores	: 2
    #apicid		: 0
    #initial apicid	: 0
    #fpu		: yes
    #fpu_exception	: yes
    #cpuid level	: 13
    #wp		: yes
    #flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmo
    #n pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 fma cx16 xtpr pdcm pcid sse4_1 sse4_2 movbe popcnt tsc_deadline_timer 
    #aes xsave avx f16c rdrand lahf_lm abm ida arat epb xsaveopt pln pts dtherm tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid
    #bogomips	: 3391.99
    #clflush size	: 64
    #cache_alignment	: 64
    #address sizes	: 39 bits physical, 48 bits virtual
    #power management:

    crypto = Hash.new
		file = Pathname.new("/proc/crypto")
    lines = file.readlines
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      if ( line.length == 1 )
        event = LogStash::Event.new( 
              "crypto"       => crypto,
              "file"          => file.to_s,
              "host"          => @host, 
              "type"          => "crypto" )
        decorate(event)
        queue << event
        next
      end
      m = line.strip.split(/[:\s]+/)
      if ( m && m.length >= 2 )
        crypto[m[0]] = m[1]
      end
    }
end

def readWireless(queue)
    #  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
		file = Pathname.new("/proc/net/wireless")
    #Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
    #face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
    #  wlan0: 0000   32.  -78.  -256        0      0      0     19     89        0
    lines = file.readlines
    junk = lines.shift
    junk = lines.shift
    lines.each { |line|
      #@logger.info? && @logger.info("LINE: "+line)
      m = line.strip.split(/[:\s]+/)
      #puts(m)
      if (m && m.length >= 11 )
      event = LogStash::Event.new(
              "raw"           => line, 
              "iface"         => m[0], 
              "status"        => m[1],
              "linkQuality"   => m[2],
              "levelQuality"  => m[3],
              "noiseQulity"   => m[4],
              "nwidDiscard"   => m[5],
              "cryptDiscard"  => m[6],
              "fragDiscard"   => m[7],
              "retryDiscard"  => m[8],
              "miscDiscard"   => m[9],
              "missedBeacon"  => m[10],
              "we22"          => m[11],
              "file"          => file.to_s,
              "host"          => @host, 
              "type"          => "wireless" )
              decorate(event)
              queue << event
      end
  }

end
def readSysIpcShm(queue)
    #  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
		file = Pathname.new("/proc/sysvipc/shm")
    #   key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap
    #     0     589824  1600                524288  1708  1739      2  1000  1000  1000  1000 1433801660 1433801660 1433801659                 12288                     0
    #     0     491521  1600                524288  1479   871      2  1000  1000  1000  1000 1433801655          0 1433801655                147456                     0
    lines = file.readlines
    junk = lines.shift
    lines.each { |line|
      m = line.strip.split(/[\s]+/)
      if (m && m.length >= 14 )
      event = LogStash::Event.new(
              "raw"   => line, 
              "key"   => m[0], 
              "shmid" => m[1].to_i,
              "perms" => m[2].to_i,
              "size"  => m[3].to_i,
              "cpid"  => m[4].to_i,
              "lpid"  => m[5].to_i,
              "nattch"=> m[6].to_i,
              "uid"   => m[7].to_i,
              "gid"   => m[8].to_i,
              "cuid"  => m[9].to_i,
              "cgid"  => m[10].to_i,
              "atime" => m[11].to_i,
              "dtime" => m[12].to_i,
              "ctime" => m[13].to_i,
              "rss"   => m[14].to_i,
              "file"  => file.to_s,
              "host"  => @host, 
              "type"  => "sysipcshm" )
              decorate(event)
              queue << event
      end
  }

end

  def run(queue)
    loop do
      begin
      start = Time.now
      readVmStats(queue)     if @vmstats
      readLoadAverage(queue) if @loadavg
      readMemInfo(queue)     if @meminfo
      readPidStats(queue)    if @pidstats
      readDiskStats(queue)   if @diskstats
      readMounts(queue)      if @mounts
      readNetDev(queue)      if @netdev
      readCpuInfo(queue)     if @cpuinfo
      readCrypto(queue)      if @crypto
      readWireless(queue)    if @wireless
      readSysIpcShm(queue)   if @sysipcshm
      duration = Time.now - start
      @logger.info("Parsing completed", :duration => duration, :interval => @interval )
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
        #puts exception.message 
        puts exception.backtrace
        raise
      end # rescue
    end # loop
  end # def run
end # class LogStash::Inputs::Example