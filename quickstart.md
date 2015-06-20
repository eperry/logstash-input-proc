# Logstash Plugin

## To install for use
```
${LS_HOME}/bin/plugin install logstash-input-proc
```

## Example Config all features enabled
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
##Example Minimal

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

