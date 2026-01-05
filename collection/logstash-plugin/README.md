https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules

https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/microsoft-sentinel-log-analytics-logstash-output-plugin

```sh
podman exec logstash logstash-plugin install microsoft-sentinel-log-analytics-logstash-output-plugin
```

```
/usr/share/logstash/config/
└───pipelines.yml
```

https://github.com/joetanx/sentinel/blob/bd63363ec7688359bc9066f8b8557146539cb0c5/collection/logstash-plugin/pipelines.yml#L1-L9

```
/usr/share/logstash/pipeline/
├───elasticsearch.conf
├───main.conf
├───sentinel-securityevent.conf
└───sentinel-syslog.conf
```

![](https://github.com/user-attachments/assets/218c30aa-751b-48ab-9b98-aab5e68842a3)

![](https://github.com/user-attachments/assets/85775cc6-440a-41ca-9f61-90c0e11c7a12)
