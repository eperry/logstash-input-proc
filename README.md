![](https://github.com/eperry/logstash-input-proc/wiki/MemInfoDashboard.png)

# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elasticsearch/logstash).

This plugin is to read the /proc virtual file system , decode the files in it.
I am using the following pages for reference 

- http://man7.org/linux/man-pages/man5/proc.5.html




## Documentation


### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.
 ```sh
bundle install
```

- Then clone this repo
- You will need to either clone the logstash repo or download the binary



### 2. Running the unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-input-proc", :path => "/your/local/logstash-input-proc"
```
- Install plugin
```sh
bin/plugin install --no-verify
```
- install Ruby Debug
```sh
bin/plugin install logstash-codec-rubydebug
```
- Run Logstash with your plugin
```sh
bin/logstash -e 'input {proc {interval=>60}}  output { stdout{ codec=>"rubydebug"}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-output-proc.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/plugin install /your/local/plugin/logstash-input-proc.gem
```
- Start Logstash and proceed to test the plugin
- 
# Example Config all features enabled
```ruby
input {
    proc {
        interval=>60
        vmstats =>{ }
        loadavg =>{ }
        meminfo =>{ }
        pidstats =>{ 
            user => "root"
        }
        
    }
}

output { 
    stdout{ 
        codec=>"rubydebug"
    }
}
```
#Example Minimal

```ruby
input {
    proc {
        interval=>60
        meminfo =>{ }
    }
}

output { 
    stdout{ 
        codec=>"rubydebug"
    }
}
```

## 3.0 Kibana Dashboards

Still a work in progress but I have saved a copy of the Kibana 4.1 dashboards I have created
in the ~/Kibana Directory, you should be able to import them from the Kibana->settings->Objects pages

These dashboards are right now a way of me validating the data loaded in elasticsearch is usable and provide an example for others to work off of. They work with the setup
of elasticsearch as defined below.


## 4.0 Elasticsearch Templates

In the ~/ElasitcSearch Directory are all the Elasticsearch templates I am developing to work with this plugin. 
While they may not be exactly what you need they are a good start. 

I load them via the ${ES_HOME/config/templates directory but feel free to load them in your preffered way 

These templates are based on the fact that your indexes for the data are created like so:
```
output { 
    elasticsearch { 
       host => localhost 
       index => "%{type}-%{+YYYY.MM.dd}"
    }
}
```

