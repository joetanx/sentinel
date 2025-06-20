## 1. Introduction

Organization may sometimes be required to verify if a certain file hash indicators exist in the environment

This can be achieved by monitoring sysmon events and matching the file hashes against the indicators

## 2. Install sysmon

### 2.1. Sysmon for Windows

Download and extract sysmon files:

```pwsh
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile .\Sysmon.zip
Expand-Archive -Path .\Sysmon.zip -DestinationPath .
```

Common sysmon configuration file for Windows by SwiftOnSecurity: https://github.com/SwiftOnSecurity/sysmon-config

```pwsh
Invoke-WebRequest https://github.com/SwiftOnSecurity/sysmon-config/raw/refs/heads/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
```

Edit `HashAlgorithms` element to specify the desired hashing algorithms

Example:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
⋮
```

Install sysmon with the desired configuration:

```pwsh
Start-Process -FilePath Sysmon64.exe -ArgumentList '-accepteula -i sysmonconfig-export.xml' -NoNewWindow -Wait
```

### 2.2. Sysmon for Linux

Install sysmon package - Ubuntu:

```sh
curl -sLO https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb
apt update
apt -y install sysmonforlinux
```

Install sysmon package - RHEL:

```sh
rpm -Uvh https://packages.microsoft.com/config/rhel/$(. /etc/os-release && echo ${VERSION_ID%%.*})/packages-microsoft-prod.rpm
yum -y install sysmonforlinux
```

Common sysmon configuration file for Linux by MSTIC (Microsoft Threat Intelligence Center): https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux/configs

```sh
curl -sLO https://github.com/microsoft/MSTIC-Sysmon/raw/refs/heads/main/linux/configs/main.xml
sed -i '/Sysmon schemaversion/a\  <HashAlgorithms>MD5,SHA256</HashAlgorithms>' main.xml
```

Edit `HashAlgorithms` element to specify the desired hashing algorithms

Example:

```xml
<Sysmon schemaversion="4.82">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
⋮
```

Install sysmon with the desired configuration:

```sh
sysmon -i main.xml
```

### 2.3. File hashes in sysmon events

Sysmon supports MD5, SHA1, SHA256 and IMPHASH

Wildcard `*` can be used for the `<HashAlgorithms>` element to include all supported hashing algorithms

(i.e. `<HashAlgorithms>*</HashAlgorithms>` == `<HashAlgorithms>md5,sha1,sha256,IMPHASH</HashAlgorithms>`)

The sysmon events that have file hashes are:

|Event|Windows|Linux|
|---|---|---
|ProcessCreate|✓|✓|
|DriverLoad|✓|✓|
|ImageLoad|✓|✓|
|FileCreateStreamHash|✓|✓|
|FileDelete|✓|✓|
|ClipboardChange|✓|✓|
|FileDeleteDetected|✓|✓|
|FileBlockExecutable|✓||
|FileBlockShredding|✓||
|FileExecutableDetected|✓||

This can be confirmed with `sysmon -s` and check the schema for events that has `Hashes` field

## 3. Parsing sysmon event in Sentinel

### 3.1. Example sysmon event received in Sentinel

<Details><Summary>Windows - received in <code>EventData</code> field:</Summary>

```xml
<EventData>
  <Data Name='RuleName'>-</Data>
  <Data Name='UtcTime'>2025-06-19 13:16:18.169</Data>
  <Data Name='ProcessGuid'>{5bd102c8-0da2-6854-4d02-000000000800}</Data>
  <Data Name='ProcessId'>8848</Data>
  <Data Name='Image'>C:\Windows\System32\curl.exe</Data>
  <Data Name='FileVersion'>8.10.1</Data>
  <Data Name='Description'>The curl executable</Data>
  <Data Name='Product'>The curl executable</Data>
  <Data Name='Company'>curl, https://curl.se/</Data>
  <Data Name='OriginalFileName'>curl.exe</Data>
  <Data Name='CommandLine'>curl  --version</Data>
  <Data Name='CurrentDirectory'>C:\Users\Administrator\</Data>
  <Data Name='User'>LAB\Administrator</Data>
  <Data Name='LogonGuid'>{5bd102c8-0c33-6854-3750-ba0000000000}</Data>
  <Data Name='LogonId'>0xba5037</Data>
  <Data Name='TerminalSessionId'>3</Data>
  <Data Name='IntegrityLevel'>High</Data>
  <Data Name='Hashes'>MD5=AC08320E81FF7904CB903FE85EACC731,SHA256=30611CC7942909B7BF8205B9C2762C03053B6E5F375CCF4A83467F1B9B045C9E</Data>
  <Data Name='ParentProcessGuid'>{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name='ParentProcessId'>6916</Data>
  <Data Name='ParentImage'>-</Data>
  <Data Name='ParentCommandLine'>-</Data>
  <Data Name='ParentUser'>-</Data>
</EventData>
```

</Details>

<Details><Summary>Linux - received in <code>SyslogMessage</code> field:</Summary>
	
```xml
<Event>
  <System>
    <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2025-06-19T13:16:36.927819000Z"/>
    <EventRecordID>581</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4111" ThreadID="4111"/>
    <Channel>Linux-Sysmon/Operational</Channel>
    <Computer>gitlab.vx</Computer>
    <Security UserId="0"/>
  </System>
  <EventData>
    <Data Name="RuleName">TechniqueID=T1105,TechniqueName=Ingress Tool Transfer</Data>
    <Data Name="UtcTime">2025-06-19 13:16:36.932</Data>
    <Data Name="ProcessGuid">{a8fa4b5d-0db4-6854-8d8e-0c28645d0000}</Data>
    <Data Name="ProcessId">8246</Data>
    <Data Name="Image">/usr/bin/curl</Data>
    <Data Name="FileVersion">-</Data>
    <Data Name="Description">-</Data>
    <Data Name="Product">-</Data>
    <Data Name="Company">-</Data>
    <Data Name="OriginalFileName">-</Data>
    <Data Name="CommandLine">curl --version</Data>
    <Data Name="CurrentDirectory">/root</Data>
    <Data Name="User">root</Data>
    <Data Name="LogonGuid">{a8fa4b5d-0c55-6854-0000-000000000000}</Data>
    <Data Name="LogonId">0</Data>
    <Data Name="TerminalSessionId">3</Data>
    <Data Name="IntegrityLevel">no level</Data>
    <Data Name="Hashes">MD5=81756ec4f1cd13bfa20105e9d1b3791b,SHA256=aca992dba6da014cd5baaa739624e68362c8930337f3a547114afdbd708d06a4</Data>
    <Data Name="ParentProcessGuid">{00000000-0000-0000-0000-000000000000}</Data>
    <Data Name="ParentProcessId">3121</Data>
    <Data Name="ParentImage">-</Data>
    <Data Name="ParentCommandLine">-</Data>
    <Data Name="ParentUser">-</Data>
  </EventData>
</Event>
```

</Details>

### 3.2. Parse sysmon EventData with [parse_xml()](https://learn.microsoft.com/en-us/kusto/query/parse-xml-function)

#### 3.2.1. Windows

KQL to parse `EventData`:

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "Hashes"
| extend parsed = parse_xml(EventData)
```

<Details><Summary><code>parse_xml(EventData)</code> results in a <i>dynamic array</i> with the name and value of each element in <code>@Name</code> and <code>#test</code> fields</Summary>

```json
{
  "EventData": {
    "Data": [
      {
        "#text": "-",
        "@Name": "RuleName"
      },
      {
        "#text": "2025-06-19T13:16:18.1690000Z",
        "@Name": "UtcTime"
      },
      {
        "#text": "{5bd102c8-0da2-6854-4d02-000000000800}",
        "@Name": "ProcessGuid"
      },
      {
        "#text": "8848",
        "@Name": "ProcessId"
      },
      {
        "#text": "C:\\Windows\\System32\\curl.exe",
        "@Name": "Image"
      },
      {
        "#text": "8.10.1",
        "@Name": "FileVersion"
      },
      {
        "#text": "The curl executable",
        "@Name": "Description"
      },
      {
        "#text": "The curl executable",
        "@Name": "Product"
      },
      {
        "#text": "curl, https://curl.se/",
        "@Name": "Company"
      },
      {
        "#text": "curl.exe",
        "@Name": "OriginalFileName"
      },
      {
        "#text": "curl --version",
        "@Name": "CommandLine"
      },
      {
        "#text": "C:\\Users\\Administrator\\",
        "@Name": "CurrentDirectory"
      },
      {
        "#text": "LAB\\Administrator",
        "@Name": "User"
      },
      {
        "#text": "{5bd102c8-0c33-6854-3750-ba0000000000}",
        "@Name": "LogonGuid"
      },
      {
        "#text": "0xba5037",
        "@Name": "LogonId"
      },
      {
        "#text": "3",
        "@Name": "TerminalSessionId"
      },
      {
        "#text": "High",
        "@Name": "IntegrityLevel"
      },
      {
        "#text": "MD5=AC08320E81FF7904CB903FE85EACC731,SHA256=30611CC7942909B7BF8205B9C2762C03053B6E5F375CCF4A83467F1B9B045C9E",
        "@Name": "Hashes"
      },
      {
        "#text": "{00000000-0000-0000-0000-000000000000}",
        "@Name": "ParentProcessGuid"
      },
      {
        "#text": "6916",
        "@Name": "ParentProcessId"
      },
      {
        "#text": "-",
        "@Name": "ParentImage"
      },
      {
        "#text": "-",
        "@Name": "ParentCommandLine"
      },
      {
        "#text": "-",
        "@Name": "ParentUser"
      }
    ]
  }
}
```

</Details>

#### 3.2.2. Linux

KQL to parse `SyslogMessage`:

```kql
Syslog
| where SyslogMessage contains "Linux-Sysmon" and SyslogMessage contains "Hashes"
| extend parsed = parse_xml(SyslogMessage)
```

<Details><Summary><code>parse_xml(SyslogMessage)</code> results in a <i>dynamic array</i> with the name and value of each element in <code>@Name</code> and <code>#test</code> fields</Summary>

```json
{
  "Event": {
    "System": {
      "Provider": {
        "@Name": "Linux-Sysmon",
        "@Guid": "{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"
      },
      "EventID": 1,
      "Version": 5,
      "Level": 4,
      "Task": 1,
      "Opcode": 0,
      "Keywords": "0x8000000000000000",
      "TimeCreated": {
        "@SystemTime": "2025-06-19T13:16:36.9278190Z"
      },
      "EventRecordID": 581,
      "Correlation": null,
      "Execution": {
        "@ProcessID": 4111,
        "@ThreadID": 4111
      },
      "Channel": "Linux-Sysmon/Operational",
      "Computer": "gitlab.vx",
      "Security": {
        "@UserId": 0
      }
    },
    "EventData": {
      "Data": [
        {
          "#text": "TechniqueID=T1105,TechniqueName=Ingress Tool Transfer",
          "@Name": "RuleName"
        },
        {
          "#text": "2025-06-19T13:16:36.9320000Z",
          "@Name": "UtcTime"
        },
        {
          "#text": "{a8fa4b5d-0db4-6854-8d8e-0c28645d0000}",
          "@Name": "ProcessGuid"
        },
        {
          "#text": "8246",
          "@Name": "ProcessId"
        },
        {
          "#text": "/usr/bin/curl",
          "@Name": "Image"
        },
        {
          "#text": "-",
          "@Name": "FileVersion"
        },
        {
          "#text": "-",
          "@Name": "Description"
        },
        {
          "#text": "-",
          "@Name": "Product"
        },
        {
          "#text": "-",
          "@Name": "Company"
        },
        {
          "#text": "-",
          "@Name": "OriginalFileName"
        },
        {
          "#text": "curl --version",
          "@Name": "CommandLine"
        },
        {
          "#text": "/root",
          "@Name": "CurrentDirectory"
        },
        {
          "#text": "root",
          "@Name": "User"
        },
        {
          "#text": "{a8fa4b5d-0c55-6854-0000-000000000000}",
          "@Name": "LogonGuid"
        },
        {
          "#text": "0",
          "@Name": "LogonId"
        },
        {
          "#text": "3",
          "@Name": "TerminalSessionId"
        },
        {
          "#text": "no level",
          "@Name": "IntegrityLevel"
        },
        {
          "#text": "MD5=81756ec4f1cd13bfa20105e9d1b3791b,SHA256=aca992dba6da014cd5baaa739624e68362c8930337f3a547114afdbd708d06a4",
          "@Name": "Hashes"
        },
        {
          "#text": "{00000000-0000-0000-0000-000000000000}",
          "@Name": "ParentProcessGuid"
        },
        {
          "#text": "3121",
          "@Name": "ParentProcessId"
        },
        {
          "#text": "-",
          "@Name": "ParentImage"
        },
        {
          "#text": "-",
          "@Name": "ParentCommandLine"
        },
        {
          "#text": "-",
          "@Name": "ParentUser"
        }
      ]
    }
  }
}
```

</Details>

### 3.3. Processing the dynamic array from `parse_xml`

#### 3.3.1. Using [mv-expand](https://learn.microsoft.com/en-us/kusto/query/mv-expand-operator)

`mv-expand` works on multi-value dynamic arrays or property bags to _expand_ it into multiple records
- `mv-expand` can be described as the opposite of the aggregation operators that pack multiple values into a single dynamic-typed array or property bag, such as `summarize ... make-list()` and `make-series`
- Using `mv-expand` creates duplicates rows of each row by a factor of the length of the expanded array
- `summarize` is needed after `mv-expand` to "collapse" back the data for the desired fields e.g. `OriginalFileName`/`CommandLine` and `Hashes`

Windows:

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "Hashes"
| extend parsed = parse_xml(EventData)
| mv-expand Data = parsed.EventData.Data
| summarize
  OriginalFileName = take_anyif(Data["#text"], Data["@Name"] == "OriginalFileName"),
  Hashes = take_anyif(Data["#text"], Data["@Name"] == "Hashes")
  by TimeGenerated, Computer, EventID, Account
```

Linux:

```kql
Syslog
| where SyslogMessage contains "Linux-Sysmon" and SyslogMessage contains "Hashes"
| extend parsed = parse_xml(SyslogMessage)
| mv-expand Data = parsed.Event.EventData.Data
| summarize
  CommandLine = take_anyif(Data["#text"], Data["@Name"] == "CommandLine"),
  Hashes = take_anyif(Data["#text"], Data["@Name"] == "Hashes")
  by TimeGenerated, Computer, HostIP
```

One down side of doing this is that the resultant table keeps only columns specified in `by`

#### 3.3.2. Using [mv-apply](https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator)

`mv-apply` can _apply_ a subquery to each row, and return the union of the results of all subqueries

This essentially means: for each row of the table, _apply_ a subquery, then _extend_ the table with the result of the query

In this file hash hunting case, extends the table with `OriginalFileName`/`CommandLine` and `Hashes` columns

Windows:

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "Hashes"
| extend parsed = parse_xml(EventData)
| mv-apply Data = parsed.EventData.Data on (
summarize
  OriginalFileName = take_anyif(Data["#text"], Data["@Name"] == "OriginalFileName"),
  Hashes = take_anyif(Data["#text"], Data["@Name"] == "Hashes")
)
```

Linux:

```kql
Syslog
| where SyslogMessage contains "Linux-Sysmon" and SyslogMessage contains "Hashes"
| extend parsed = parse_xml(SyslogMessage)
| mv-apply Data = parsed.Event.EventData.Data on (
summarize
  CommandLine = max(iif(Data["@Name"] == "CommandLine", Data["#text"], "")),
  Hashes = max(iif(Data["@Name"] == "Hashes", Data["#text"], ""))
)
```

### 3.4. Parse the `Hashes` field and put in columns for each algorithm

After the `Hashes` field is retrieve from `mv-apply`, [extract()](https://learn.microsoft.com/en-us/kusto/query/extract-function) can match the `Hashes` field for the desired hash regex pattern

Windows:

```kql
SecurityEvent
| where Channel contains "Microsoft-Windows-Sysmon" and EventData contains "Hashes"
| extend parsed = parse_xml(EventData)
| mv-apply Data = parsed.EventData.Data on (
summarize
  OriginalFileName = max(iif(Data["@Name"] == "OriginalFileName", Data["#text"], "")),
  Hashes = max(iif(Data["@Name"] == "Hashes", Data["#text"], ""))
)
| extend 
  MD5 = extract(@"MD5=([A-Fa-f0-9]{32})", 1, Hashes),
  SHA256 = extract(@"SHA256=([A-Fa-f0-9]{64})", 1, Hashes)
```

![image](https://github.com/user-attachments/assets/3f0caf33-8814-4b6c-a285-33d3d7406922)

Linux:

```kql
Syslog
| where SyslogMessage contains "Linux-Sysmon" and SyslogMessage contains "Hashes"
| extend parsed = parse_xml(SyslogMessage)
| mv-apply Data = parsed.Event.EventData.Data on (
summarize
  CommandLine = max(iif(Data["@Name"] == "CommandLine", Data["#text"], "")),
  Hashes = max(iif(Data["@Name"] == "Hashes", Data["#text"], ""))
)
| extend 
  MD5 = extract(@"MD5=([A-Fa-f0-9]{32})", 1, Hashes),
  SHA256 = extract(@"SHA256=([A-Fa-f0-9]{64})", 1, Hashes)
```

![image](https://github.com/user-attachments/assets/797d654b-de2b-4131-b4fb-9ab4e88c503c)
