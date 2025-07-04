```kql
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let EventQueryName = SecurityEvent
| where TimeGenerated >= ago(dt_lookBack) and Channel contains "Microsoft-Windows-Sysmon" and EventData contains "QueryName"
| extend parsed = parse_xml(EventData)
| mv-apply Data = parsed.EventData.Data on (summarize QueryName = tolower(take_anyif(Data["#text"], Data["@Name"] == "QueryName")));
let TIDomainName = ThreatIntelligenceIndicator
| where isnotempty(DomainName) and TimeGenerated >= ago(ioc_lookBack)
| extend DomainName = tolower(DomainName);
EventQueryName
| join kind=innerunique TIDomainName on $left.QueryName == $right.DomainName
| summarize arg_max(TimeGenerated, *) by Computer, QueryName
```
