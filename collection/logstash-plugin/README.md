## 1. Logs flow

Sentinel supports [ingestion using Logstash](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules) via the [logs ingestion api](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)

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

## 2. Data sources

- Windows:
  - Direct collection with Winlogbeat: Winlogbeat sends events directly to Logstash over the Beats protocol on port 5044
  - Centralized collection via Windows Event Collector (WEC): leverage Windows Event Forwarding (WEF) to consolidate events to a WEC server running Winlogbeat to forward to Logstash
- Linux: Send syslog directly to Logstash TCP input on port 1514

Details on ingesting logs to elastic stack [here](https://github.com/joetanx/setup/tree/main/elastic)

## 3. Logstash pipelines

The example pipeline files in this directory are used in Logstash in this structure:

```
/usr/share/logstash/
├───config/
│   └───pipelines.yml
└───pipeline/
    ├───elasticsearch.conf
    ├───main.conf
    ├───sentinel-securityevent.conf
    └───sentinel-syslog.conf
```

The [pipelines.yml](/collection/logstash-plugin/pipelines.yml) is defines all available pipelines and their corresponding configuration files; Logstash reads this file on startup to initialize multiple concurrent pipelines

https://github.com/joetanx/sentinel/blob/bd63363ec7688359bc9066f8b8557146539cb0c5/collection/logstash-plugin/pipelines.yml#L1-L9

|Pipeline|Purpose|
|---|---|
|[main](/collection/logstash-plugin/main.conf)|Entry point pipeline: receive events on TCP syslog (1514) and beats (5044) and route to downstream pipelines|
|[elasticsearch-output](/collection/logstash-plugin/elasticsearch.conf)|Both syslog and beats events are sent to Elasticsearch for local visibility via Kibana|
|[sentinel-syslog-output](/collection/logstash-plugin/sentinel-syslog.conf)|Transform syslog events to Sentinel's `Syslog` table schema and send to the table|
|[sentinel-securityevent-output](/collection/logstash-plugin/sentinel-securityevent.conf)|Transform Windows security events to Sentinel's `SecurityEvent` table schema and send to the table|

## 4. Sentinel Logstash output plugin

Logstash sends logs to Sentinel via the [microsoft-sentinel-log-analytics-logstash-output-plugin](https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/microsoft-sentinel-log-analytics-logstash-output-plugin)

Insall the plugin with `logstash-plugin install` in Logstash:

```sh
podman exec logstash logstash-plugin install microsoft-sentinel-log-analytics-logstash-output-plugin
```

### 4.1. Logs ingestion API and Data Collection Rules (DCR)

The Sentinel Logstash plugin uses logs ingestion API and DCR to send events to Sentinel

More details on setting up [here](/logs-ingestion-api)

## 5. Events received in Sentinel

### 5.1. Linux

![](https://github.com/user-attachments/assets/218c30aa-751b-48ab-9b98-aab5e68842a3)

### 5.2. Windows

![](https://github.com/user-attachments/assets/85775cc6-440a-41ca-9f61-90c0e11c7a12)
