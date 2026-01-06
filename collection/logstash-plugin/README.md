## 1. Logs flow

```mermaid
flowchart TD
  subgraph Windows data sources
    W1(with Winlogbeat)
    W2(without Winlogbeat) 
  end
  W3(Windows Event Collector<br>with Winlogbeat)
  L(Linux)
  subgraph logstash
    subgraph pipelines
      subgraph main.conf
        I1(Input:<br>tcp 1514)
        I2(Input:<br>beats 5044)
      end
      subgraph elasticsearch.conf
        F1(Filter:<br>syslog RFC 5424)
        O1(Output:<br>elasticsearch)
      end
      subgraph sentinel-syslog.conf
        F2(Filter:<br>• syslog RFC 5424<br>• map to Sentinel Syslog table schema)
        O2(Output:<br>• Sentinel plugin<br>• Syslog stream)
      end
      subgraph sentinel-securityevent.conf
        F3(Filter:<br>map to Sentinel SecurityEvent table schema)
        O3(Output:<br>• Sentinel plugin<br>• SecurityEvent stream)
      end
    end
    F1 --> O1
    F2 --> O2
    F3 --> O3
    I1 --> F1
    I1 --> F2
    I2 --> O1
    I2 --> F3
  end
  E(Elasticsearch)
  subgraph Data Collection Rule
    SD1(Stream:<br>Custom-Syslog)
    SD2(Stream:<br>Custom-SecurityEvent)
  end
  subgraph Sentinel Workspace
    T1(Table:<br>Syslog)
    T2(Table:<br>SecurityEvent)
  end
  W1 -->|beats| I2
  W2 -->|Windows Event Forwarding| W3
  W3 -->|beats| I2
  L --->|syslog| I1
  O1 -->|:9200| E
  SD1 --> T1
  SD2 --> T2
  O2 --> SD1
  O3 --> SD2
```

## 2. Sentinel Logstash plugin

https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules

https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/microsoft-sentinel-log-analytics-logstash-output-plugin

Install the Sentinel Logstash plugin:

```sh
podman exec logstash logstash-plugin install microsoft-sentinel-log-analytics-logstash-output-plugin
```

## 3. Logstash pipelines

### 3.1. Specify pipeline files in config

```
/usr/share/logstash/config/
└───pipelines.yml
```

https://github.com/joetanx/sentinel/blob/bd63363ec7688359bc9066f8b8557146539cb0c5/collection/logstash-plugin/pipelines.yml#L1-L9

### 3.2. Pipeline files:

```
/usr/share/logstash/pipeline/
├───elasticsearch.conf
├───main.conf
├───sentinel-securityevent.conf
└───sentinel-syslog.conf
```

## 4. Events received in Sentinel

### 4.1. Linux

![](https://github.com/user-attachments/assets/218c30aa-751b-48ab-9b98-aab5e68842a3)

### 4.2. Windows

![](https://github.com/user-attachments/assets/85775cc6-440a-41ca-9f61-90c0e11c7a12)
