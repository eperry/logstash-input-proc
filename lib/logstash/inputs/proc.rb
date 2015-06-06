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
      @logger.info? && @logger.info("LINE: "+line)
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

#discoverSearch(Pathname.new("/proc"))

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