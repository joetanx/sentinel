## 1. Introduction

Organizations may sometimes need to verify if attempts to connect to certain domain name indicators are occuring in the environment

The detection method varies for Windows and Linux:
- **Windows**:
  - Sysmon for Windows captures DNS queries under event ID 22 - DNSEvent (DNS query)
  - The `QueryName` in this Sysmon event can be used to match against the indicators
- **Linux**:
  - Sysmon for Linux does not support event ID 22 - DNSEvent (DNS query)
  - There are several methods to capture DNS queries - such as logging and parsing `tcpdump` - this would be more comprehensive but can be arduious and generate large volume of ingestion
  - A simpler method is to parse syslog events from the Linux hosts for domain name patterns, then match them against the indicators

## 2. Windows

### 2.1. Install sysmon

Download and extract sysmon files:

```pwsh
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile .\Sysmon.zip
Expand-Archive -Path .\Sysmon.zip -DestinationPath .
```

Common sysmon configuration file for Windows by SwiftOnSecurity: https://github.com/SwiftOnSecurity/sysmon-config

```pwsh
Invoke-WebRequest https://github.com/SwiftOnSecurity/sysmon-config/raw/refs/heads/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
```

> [!Note]
>
> This sysmon config from SwiftOnSecurity includes the `DnsQuery` section with exclusions for common benign domains

Install sysmon with the desired configuration:

```pwsh
Start-Process -FilePath Sysmon64.exe -ArgumentList '-accepteula -i sysmonconfig-export.xml' -NoNewWindow -Wait
```

### 2.2. Parsing sysmon event in Sentinel

Example sysmon event received in Sentinel:

```xml
<EventData>
  <Data Name="RuleName">-</Data>
  <Data Name="UtcTime">2025-07-08 00:04:30.453</Data>
  <Data Name="ProcessGuid">{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name="ProcessId">6255</Data>
  <Data Name="QueryName">malicious.xyz</Data>
  <Data Name="QueryStatus">0</Data>
  <Data Name="QueryResults">145.133.204.152</Data>
  <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  <Data Name="User">LAB\gabriel</Data>
</EventData>
```

Parse sysmon EventData with [parse_xml()](https://learn.microsoft.com/en-us/kusto/query/parse-xml-function):

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "QueryName"
| extend parsed = parse_xml(EventData)
```

### 2.3. Processing the dynamic array from `parse_xml`:

#### 2.3.1. Using [mv-expand](https://learn.microsoft.com/en-us/kusto/query/mv-expand-operator)

`mv-expand` works on multi-value dynamic arrays or property bags to _expand_ it into multiple records
- `mv-expand` can be described as the opposite of the aggregation operators that pack multiple values into a single dynamic-typed array or property bag, such as `summarize ... make-list()` and `make-series`
- Using `mv-expand` creates duplicates rows of each row by a factor of the length of the expanded array
- `summarize` is needed after `mv-expand` to "collapse" back the data for the desired fields e.g. `QueryName`

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "QueryName"
| extend parsed = parse_xml(EventData)
| summarize QueryName = take_anyif(Data["#text"], Data["@Name"] == "QueryName")
  by TimeGenerated, Computer
```

One down side of doing this is that the resultant table keeps only columns specified in `by`

#### 2.3.2. Using [mv-apply](https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator)

`mv-apply` can _apply_ a subquery to each row, and return the union of the results of all subqueries

This essentially means: for each row of the table, _apply_ a subquery, then _extend_ the table with the result of the query

In this domain name hunting case, extends the table with `columns` column

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "QueryName"
| extend parsed = parse_xml(EventData)
| mv-apply Data = parsed.EventData.Data on (summarize QueryName = tolower(take_anyif(Data["#text"], Data["@Name"] == "QueryName")))
```

![image](https://github.com/user-attachments/assets/b992e60c-1a8d-4c8d-b1b8-3c1d57ed5043)

## 3. Linux

Parsing syslog for domain name patterns

Regular expression:

```sh
(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,})
```

|Part|Explanation|
|---|---|
|`([a-z0-9]+(-[a-z0-9]+)*)`|Matches a sequence of lowercase letters and digits. It allows hyphens as long as they're **not at the start or end**. For example: `sub-domain123`|
|`\.`|Escaped dot `.` – matches a literal `.` between domain levels|
|`(([a-z0-9]+(-[a-z0-9]+)*\.)+)`|Groups and repeats domain labels like `www.`, `sub-domain.` etc.|
|`[a-z]{2,}`|Matches the **top-level domain** (TLD) – requires at least 2 lowercase letters (e.g. `xyz`, `cc`)|
|Outer `(...)`|Captures the full domain name|

KQL query:

```kql
Syslog
| extend DomainName = extract("(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,})",1, tolower(SyslogMessage))
```

![image](https://github.com/user-attachments/assets/8dc4fbbe-8efa-46ff-9356-fa089d4b73bf)

## 4. Import domain name indicators

Sentinel supports [bulk import](https://learn.microsoft.com/en-us/azure/sentinel/indicators-bulk-file-import) of indicators via CSV or JSON file

![image](https://github.com/user-attachments/assets/60517bb5-581f-430e-890d-cc7686b4b1c8)

A template `File Indicators import template_CSV.csv` can be downloaded from the import pane

A sample of test file hashes upload is also available [here](/indicators-test-domains.csv)

> [!Tip]
>
> Expand and read the usage instructions provided in the first row `EXPAND THIS CELL`
>
> **DELETE** the first row to import the file; otherwise, the file import fails

![image](https://github.com/user-attachments/assets/ff54af45-3ab2-4a6a-a8b7-a413a8834964)

Review `File import history` to check the status of the file import:

![image](https://github.com/user-attachments/assets/ddabe9f8-f051-4533-aef4-8e04022e6f90)

> [!Tip]
>
> File import fails as shown in the second record if the `EXPAND THIS CELL` row in the template is not deleted

Refresh to see the indicators:

![image](https://github.com/user-attachments/assets/22d70579-832b-4aab-a0c2-85e1494f1b94)

> [!Note]
>
> The import can take from 1-2 mins to several minutes to appear, even when the file import history says "Fully imported"

The indicators are in the `ThreatIntelligenceIndicator` table for query and analytics rule usage:

![image](https://github.com/user-attachments/assets/a3fb21dd-69be-4ff2-9c4f-706d96141f59)

## 5. Analytics rule to schedule file hash query and create incidents on matches

### 5.1. Threat Intelligence solution from Content hub

There is a `TI map Domain entity to Syslog` analytics rule included with the Threat Intelligence solution from Content hub

The queries and rule creation in this section is similar to this rule, adjusted with the KQL query above

![image](https://github.com/user-attachments/assets/0d355b0b-8e36-4339-9e3b-c3daed1cd111)

### 5.2. Rule logic query

Windows:

```kql
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let EventQueryName = SecurityEvent
| where TimeGenerated >= ago(dt_lookBack) and Channel contains "Microsoft-Windows-Sysmon" and EventData contains "QueryName"
| extend parsed = parse_xml(EventData)
| mv-apply Data = parsed.EventData.Data on (summarize QueryName = tolower(take_anyif(Data["#text"], Data["@Name"] == "QueryName")));
let TIDomainName = ThreatIntelligenceIndicator
| where isnotempty(DomainName) and TimeGenerated >= ago(ioc_lookBack) and Active == true and ExpirationDateTime > now()
| extend DomainName = tolower(DomainName);
EventQueryName
| join kind=inner TIDomainName on $left.QueryName == $right.DomainName
| summarize arg_max(TimeGenerated, *) by Computer, QueryName
```

Linux:

```kql
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let EventDomainName = Syslog
| where TimeGenerated >= ago(dt_lookBack)
| extend DomainName = extract("(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,})",1, tolower(SyslogMessage))
| where isnotempty(DomainName);
let TIDomainName = ThreatIntelligenceIndicator
| where isnotempty(DomainName) and TimeGenerated >= ago(ioc_lookBack) and Active == true and ExpirationDateTime > now()
| extend DomainName = tolower(DomainName);
EventDomainName
| join kind=inner TIDomainName on $left.DomainName == $right.DomainName
| summarize arg_max(TimeGenerated, *) by Computer, DomainName
```

|Query segment|Explanation|
|---|---|
|`dt_lookBack` and `ioc_lookBack`|The period for events and indicators to be included in the query|
|`let EventQueryName = …`/<br>`let EventDomainName = …`|The query name or domain name parsing query from above assigned to `EventQueryName`/`EventDomainName`|
|`let TIDomainName = …`|Select domain name indicators and assign to `TIDomainName`|
|`EventQueryName … join … TIDomainName`/<br>`EventDomainName … join … TIDomainName`|Using `inner` table `join` to select matching domain name indicators|

### 5.3. Create schedule query rule

Give it a name and select the related MITRE ATT&CK tactics and techniques (e.g. `Command And Control`)

> [!Note]
>
> Create one analytics rule each for Windows and Linux

![image](https://github.com/user-attachments/assets/3cf5f5cf-a5b1-4cac-8734-aaab94f3d5cf)

Paste in the KQL query:

> [!Note]
>
> Paste the corresponding Windows and Linux KQL queries into their respective analytics rules

![image](https://github.com/user-attachments/assets/de4e8aec-3d92-462d-86cb-02bb2d9ecc01)

Create entity mappings for to display in the incident:

![image](https://github.com/user-attachments/assets/298e7a8d-3bb6-473e-8ead-f6e52b3a938d)

Configure the schedule, alert threshold and event grouping settings:

![image](https://github.com/user-attachments/assets/045e067e-437b-4478-a2ca-34af6da5a268)

Configure incident and alert grouping settings:

![image](https://github.com/user-attachments/assets/df67451c-5f0e-4426-af34-6d249a47bb91)

Configure automation rules:

![image](https://github.com/user-attachments/assets/8d7b2415-37c3-4d75-abdb-8091d9ea34ed)

Incidents created by the analytics rules:

(The multiple domain name and file hash hunting incidents were automatically merged with the Sentinel Fusion rul)

![image](https://github.com/user-attachments/assets/d3de353a-ea1a-4774-9683-5f73e00e83af)

## 6. Domain Generation Algorithm (DGA) DNS rules from content hub

Other than hunting for specific domain names, advanced hunting techniques can also look for DGA patterns commonly seen in C&C attempts.

### 6.1. Potential communication with a Domain Generation Algorithm (DGA) based hostname (ASIM Web Session schema)

This rule identifies communication with hosts that have a domain name that might have been generated by a Domain Generation Algorithm (DGA).

DGAs are used by malware to generate rendezvous points that are difficult to predict in advance.

This detection uses the top 1 million domain names to build a model of what normal domains look like nad uses the model to identify domains that may have been randomly generated by an algorithm.

You can modify the triThreshold and dgaLengthThreshold query parameters to change Analytic Rule sensitivity.

The higher the numbers, the less noisy the rule is.

This analytic rule uses ASIM and supports any built-in or custom source that supports the ASIM WebSession schema (ASIM WebSession Schema)

```kql
let triThreshold = 500;
let querystarttime = 6h;
let dgaLengthThreshold = 8;
// fetch the cisco umbrella top 1M domains
let top1M =  (externaldata (Position:int, Domain:string)   [@"http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"]  with (format="csv", zipPattern="*.csv"));
// extract tri grams that are above our threshold - i.e. are common
let triBaseline =   top1M
  | extend Domain = tolower(extract("([^.]*).{0,7}$", 1, Domain))
  | extend AllTriGrams = array_concat(extract_all("(...)", Domain), extract_all("(...)", substring(Domain, 1)), extract_all("(...)", substring(Domain, 2)))
  | mvexpand Trigram=AllTriGrams to typeof(string)
  | summarize triCount=count() by Trigram
  | sort by triCount desc
  | where triCount > triThreshold
  | distinct Trigram;
// collect domain information from common security log, filter and extract the DGA candidate and its trigrams
let allDataSummarized =  _Im_WebSession
| where isnotempty(Url)
| extend Name = tolower(tostring(parse_url(Url)["Host"]))
| summarize NameCount=count() by Name
| where Name has "."
| where Name !endswith ".home" and Name !endswith ".lan"
// extract DGA candidate
| extend DGADomain = extract("([^.]*).{0,7}$", 1, Name)
| where strlen(DGADomain) > dgaLengthThreshold
// throw out domains with number in them
| where DGADomain matches regex "^[A-Za-z]{0,}$"
// extract the tri grams from summarized data
| extend AllTriGrams = array_concat(extract_all("(...)", DGADomain), extract_all("(...)", substring(DGADomain, 1)), extract_all("(...)", substring(DGADomain, 2)));
// throw out domains that have repeating tri's and/or >=3 repeating letters
let nonRepeatingTris =  allDataSummarized
| join kind=leftanti
(
    allDataSummarized
    | mvexpand AllTriGrams
    | summarize count() by tostring(AllTriGrams), DGADomain
    | where count_ > 1
    | distinct DGADomain
)
on DGADomain;
// find domains that do not have a common tri in the baseline
let dataWithRareTris =  nonRepeatingTris
| join kind=leftanti
(
    nonRepeatingTris
    | mvexpand AllTriGrams
    | extend Trigram = tostring(AllTriGrams)
    | distinct Trigram, DGADomain
    | join kind=inner
    (
        triBaseline
    )
    on Trigram
    | distinct DGADomain
)
on DGADomain;
dataWithRareTris
// join DGAs back on connection data
| join kind=inner
(
    _Im_WebSession
    | where isnotempty(Url)
    | extend Url = tolower(Url)
    | summarize arg_max(TimeGenerated, EventVendor,  SrcIpAddr) by Url
    | extend Name=tostring(parse_url(Url)["Host"])
    | summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by Name, SrcIpAddr, Url
)
on Name
| project StartTime, EndTime, Name, DGADomain, SrcIpAddr, Url, NameCount
```

### 6.2. Possible contact with a domain generated by a DGA

Identifies contacts with domains names in CommonSecurityLog that might have been generated by a Domain Generation Algorithm (DGA).

DGAs can be used by malware to generate rendezvous points that are difficult to predict in advance.

This detection uses the Alexa Top 1 million domain names to build a model of what normal domains look like.

It uses this to identify domains that may have been randomly generated by an algorithm.

The triThreshold is set to 500 - increase this to report on domains that are less likely to have been randomly generated, decrease it for more likely.

The start time and end time look back over 6 hours of data and the dgaLengthThreshold is set to 8 - meaning domains whose length is 8 or more are reported.

NOTE - The top1M csv zip file used in the query is dynamic and may produce different results over various time periods.

It's important to cross-check the events against the entities involved in the incident.

```kql
let triThreshold = 500;
let startTime = 6h;
let dgaLengthThreshold = 8;
// fetch the alexa top 1M domains
let top1M =  (externaldata (Position:int, Domain:string)   [@"http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"]  with (format="csv", zipPattern="*.csv"));
// extract tri grams that are above our threshold - i.e. are common
let triBaseline =   top1M
| extend Domain = tolower(extract("([^.]*).{0,7}$", 1, Domain))
| extend AllTriGrams = array_concat(extract_all("(...)", Domain), extract_all("(...)", substring(Domain, 1)), extract_all("(...)", substring(Domain, 2)))
| mvexpand Trigram=AllTriGrams
| summarize triCount=count() by tostring(Trigram)
| sort by triCount desc
| where triCount > triThreshold
| distinct Trigram;
// collect domain information from common security log, filter and extract the DGA candidate and its trigrams
let allDataSummarized =   CommonSecurityLog
| where TimeGenerated > ago(startTime)
| where isnotempty(DestinationHostName)
| extend Name = tolower(DestinationHostName)
| distinct Name
| where Name has "."
| where Name !endswith ".home" and Name !endswith ".lan"
// extract DGA candidate
| extend DGADomain = extract("([^.]*).{0,7}$", 1, Name)
| where strlen(DGADomain) > dgaLengthThreshold
// throw out domains with number in them
| where DGADomain matches regex "^[A-Za-z]{0,}$"
// extract the tri grams from summarized data
| extend AllTriGrams = array_concat(extract_all("(...)", DGADomain), extract_all("(...)", substring(DGADomain, 1)), extract_all("(...)", substring(DGADomain, 2)));
// throw out domains that have repeating tri's and/or >=3 repeating letters
let nonRepeatingTris =  allDataSummarized
| join kind=leftanti
(
    allDataSummarized
    | mvexpand AllTriGrams
    | summarize count() by tostring(AllTriGrams), DGADomain
    | where count_ > 1
    | distinct DGADomain
)
on DGADomain;
// find domains that do not have a common tri in the baseline
let dataWithRareTris =  nonRepeatingTris
| join kind=leftanti
(
    nonRepeatingTris
    | mvexpand AllTriGrams
    | extend Trigram = tostring(AllTriGrams)
    | distinct Trigram, DGADomain
    | join kind=inner
    (
        triBaseline
    )
    on Trigram
    | distinct DGADomain
)
on DGADomain;
dataWithRareTris
// join DGAs back on connection data
| join kind=inner
(
    CommonSecurityLog
    | where TimeGenerated > ago(startTime)
    | where isnotempty(DestinationHostName)
    | extend DestinationHostName = tolower(DestinationHostName)
    | project-rename Name=DestinationHostName, DataSource=DeviceVendor
    | summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by Name, SourceIP, DestinationIP, DataSource
)
on Name
| project StartTime, EndTime, Name, DGADomain, SourceIP, DestinationIP, DataSource
```
