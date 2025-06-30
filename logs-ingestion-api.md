## 1. Prepare demo application

Create the demo application and test client credential flow by following section 1. and 2. of [OAuth 2.0 with Entra identity](https://github.com/joetanx/mslab/blob/main/oauth-2.0-flows.md)

## 2. Setup data collection

### 2.1. Create DCE (Data Collection Endpoint)

![image](https://github.com/user-attachments/assets/90ea044f-63bf-41a7-b0ff-58b83710f54d)

### 2.2. Create DCR (Data Collection Rule)

#### 2.2.1. Required information for the DCR

DCR Resource ID:

![image](https://github.com/user-attachments/assets/e536484c-0cdc-40a6-9022-890f9e080c87)

Target LAW (Log Analytics Workspace) Resource ID:

![image](https://github.com/user-attachments/assets/bdf59b1a-c6a5-4b38-ae2b-78d3c9ba8505)

#### 2.2.2. DCR template

The DCR is the method to ingest events into Log Analytics, the DCR configuration in Azure portal provides typical settings to collect Windows and Linux events:

![image](https://github.com/user-attachments/assets/5fbde86a-40e9-4d7e-a9d9-df545a15e967)

DCRs for the logs ingestion API must define the schema of the incoming stream in the `streamDeclarations` section of the DCR definition

The `resource` section of a DCR template is where the data flow is defined:

|Section|Description|
|---|---|
|`streamDeclarations`|Contains the exact schema of the incoming stream i.e. the columns of the destination table to be ingested to|
|`destinations`|The destination LAW|
|`dataFlows`|The routing of the events: `streams` → `destinations` → `transformKql` → `outputStream`|
|`dataFlows`.`streams`|The incoming stream listed in `streamDeclarations`|
|`dataFlows`.`destinations`|The destination LAW listed in `destinations`|
|`dataFlows`.`transformKql`|The KQL query to apply on the incoming stream to perform [ingestion-time transformation](https://learn.microsoft.com/en-us/azure/sentinel/configure-data-transformation)<br>`source>` means no transformation is performed|
|`dataFlows`.`outputStream`|The table in the workspace specified under the `destinations` property the data will be sent to.|

The format of a DCR with columns truncated for brevity:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "dataCollectionRuleName": {
      "type": "string",
      "metadata": {
        "description": "Specifies the name of the Data Collection Rule to create."
      }
    },
    "location": {
      "defaultValue": "[resourceGroup().location]",
      "type": "string",
      "metadata": {
        "description": "Specifies the location in which to create the Data Collection Rule."
      }
    },
    "workspaceResourceId": {
      "type": "string",
      "metadata": {
        "description": "Specifies the Azure resource ID of the Log Analytics workspace to use."
      }
    },
    "endpointResourceId": {
      "type": "string",
      "metadata": {
        "description": "Specifies the Azure resource ID of the Data Collection Endpoint to use."
      }
    }
  },
  "resources": [{
    "type": "Microsoft.Insights/dataCollectionRules",
    "apiVersion": "2021-09-01-preview",
    "name": "[parameters('dataCollectionRuleName')]",
    "location": "[parameters('location')]",
    "properties": {
      "dataCollectionEndpointId": "[parameters('endpointResourceId')]",
      "streamDeclarations": {
        "Custom-CommonSecurityLog": {
          "columns": [
              <list-of-columns-in-the-CommonSecurityLog-table>
          ]
        },
        "Custom-SecurityEvent": {
          "columns": [
              <list-of-columns-in-the-SecurityEvent-table>
          ]
        },
        "Custom-Syslog": {
          "columns": [
              <list-of-columns-in-the-Syslog-table>
          ]
        },
        "Custom-WindowsEvent": {
          "columns": [
              <list-of-columns-in-the-WindowsEvent-table>
          ]
        }
      },
      "destinations": {
        "logAnalytics": [{
          "workspaceResourceId": "[parameters('workspaceResourceId')]",
          "name": "logAnalyticsWorkspace"
        }]
      },
      "dataFlows": [{
          "streams": [
            "Custom-CommonSecurityLog"
          ],
          "destinations": [
            "logAnalyticsWorkspace"
          ],
          "transformKql": "source",
          "outputStream": "Microsoft-CommonSecurityLog"
        },
        {
          "streams": [
            "Custom-SecurityEvent"
          ],
          "destinations": [
            "logAnalyticsWorkspace"
          ],
          "transformKql": "source",
          "outputStream": "Microsoft-SecurityEvent"
        },
        {
          "streams": [
            "Custom-Syslog"
          ],
          "destinations": [
            "logAnalyticsWorkspace"
          ],
          "transformKql": "source",
          "outputStream": "Microsoft-Syslog"
        },
        {
          "streams": [
            "Custom-WindowsEvent"
          ],
          "destinations": [
            "logAnalyticsWorkspace"
          ],
          "transformKql": "source",
          "outputStream": "Microsoft-WindowsEvent"
        }
      ]
    }
  }],
  "outputs": {
    "dataCollectionRuleId": {
      "type": "string",
      "value": "[resourceId('Microsoft.Insights/dataCollectionRules', parameters('dataCollectionRuleName'))]"
    }
  }
}
```

More details on [DCR data flow](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure#overview-of-dcr-data-flow)

A DCR template for ingestion to the Sentinel tables (`CommonSecurityLog`, `SecurityEvent`, `Syslog`, `WindowsEvent`) is available [here](/dcr_template.json):

#### 2.2.3. Deploy the DCR template

- Go to `Deploy a custom template`
- Select `Build your own template in the editor`
- Copy and paste the [dcr_template.json](dcr_template.json)

![image](https://github.com/user-attachments/assets/cce912ef-25a0-4d8a-8a50-f8e74ca59e99)

Paste the DCE and LAW Resource IDs

![image](https://github.com/user-attachments/assets/37e125d3-5c39-4faa-a2e6-100e4295f775)

### 2.3. Add role assignment for DemoApp to the DCR

> [!Note]
>
> In Entra, app registration contains information about the application, usually including URLs for SSO (Single Sign-On)
>
> An enterprise application is created automatically when an app is registered
>
> The enterprise application resource is the service prinicipal (i.e. service account or machine identity) of the application
>
> Permissions can be granted to the application by role assignment to the application resource

DCR → Access Control (IAM) → Add role assignment

Select `Monitoring Metrics Publisher` role:

![image](https://github.com/user-attachments/assets/64047422-7df0-4dbf-8547-9e5c975eaedd)

Select the demo application:

> [!Tip]
>
> https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#assign-a-role-to-the-application
>
> By default, Microsoft Entra applications aren't displayed in the available options. Search for the application by name to find it.

![image](https://github.com/user-attachments/assets/b9e43b28-43c8-452f-a5af-c717662fcada)

## 2.4. Retrieve the logs ingestion API URI

Ref: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview#uri

The URI consists of:
- DCE
- Region
- DCR Immutable ID
- Stream Name
- API version

```pwsh
{Endpoint}.{Region}.ingest.monitor.azure.com//dataCollectionRules/{DCR Immutable ID}/streams/{Stream Name}?api-version=2023-01-01
```

|Field|Description|
|---|---|
|Data collection endpoint|Data collection endpoint (DCE) in the format `https://<endpoint-name>.<identifier>.<region>.ingest.monitor.azure.com`.<br>![image](https://github.com/user-attachments/assets/25ec6bdc-4c0a-4030-8ddd-93e0bf2974dd)|
|Data collection rule ID|DCR Immutable ID:<br>![image](https://github.com/user-attachments/assets/15330cbf-1fee-4dc2-b784-6bc9aed11826)|
|Stream name|The `streamDeclarations` defined in the DCR:<br>![image](https://github.com/user-attachments/assets/1378d8a2-b775-41c4-bd9c-9ad162fb2745)|

An Azure Resource Graph Explorer query can retrieve the required information:

```kql
Resources
| where type =~ 'microsoft.insights/datacollectionrules'
| mv-expand Streams= properties['dataFlows']
| project name, id, DCE = tostring(properties['dataCollectionEndpointId']), ImmutableId = properties['immutableId'], StreamName = Streams['streams'][0]
| join kind=leftouter (Resources
| where type =~ 'microsoft.insights/datacollectionendpoints'
| project name,  DCE = tostring(id), endpoint = properties['logsIngestion']['endpoint']) on DCE
| project name, StreamName, Endpoint = strcat(endpoint, '/dataCollectionRules/',ImmutableId,'/streams/',StreamName,'?api-version=2023-01-01')
```

![image](https://github.com/user-attachments/assets/e60f2923-c618-4f92-ab36-2960595416f8)

## 3. Logs ingestion API

### 3.1. API Authentication - client credential flow example using PowerShell

> [!Tip]
>
> The demo application can be authenticated via either client credential or authorization code flow by following section 2. and 3. of [OAuth 2.0 with Entra identity](https://github.com/joetanx/mslab/blob/main/oauth-2.0-flows.md)

The `scope` required for logs ingestion is `https://monitor.azure.com/.default`

Prepare authentication parameters:

```pwsh
$tenant = '<tenant-id>'
$clientid = '<client-id>'
$clientsecret = '<client-secret>'
$token_endpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
$body=@{
  client_id = $clientid
  client_secret = $clientsecret
  grant_type = 'client_credentials'
  scope = 'https://monitor.azure.com/.default'
}
```

Request for access token:

> [!Tip]
>
> The `Tee-Object` command in PowerShell works similar to `tee` in Linux
>
> it sends the output of the previous command to both the console and the specified variable

```pwsh
Invoke-RestMethod $token_endpoint -Method Post -Body $body | Tee-Object -Variable token
```

Example output:

```pwsh
token_type expires_in ext_expires_in access_token
---------- ---------- -------------- ------------
Bearer           3599           3599 <access-token-jwt>
```

The logs ingestion API expect access token in the `Authorization` header in the format of: `Bearer: <access-token-jwt>`

Prepare the request header:

```pwsh
$headers = @{
  Authorization='Bearer '+$token.access_token
}
```

### 3.2. Data preparation using PowerShell

The logs ingestion API expects the data to be in JSON; specifically, it should be an array of events:

```json
[
  {
    "alpha": "valueA1",
    "bravo": "valueB1",
    "charlie": "valueC1"
  },
  {
    "alpha": "valueA2",
    "bravo": "valueB2",
    "charlie": "valueC2"
  },
  {
    "alpha": "valueA3",
    "bravo": "valueB3",
    "charlie": "valueC3"
  },
]
```

The `@[]` and `@{}` notations can be used to create the data object in PowerShell

The data above can be created as an array of objects and using `ConvertTo-Json` to format it as JSON string:

```pwsh
$body = @(
  @{
    alpha='valueA1'
    bravo='valueB1'
    charlie='valueC1'
  }
  @{
    alpha='valueA2'
    bravo='valueB2'
    charlie='valueC2'
  }
  @{
    alpha='valueA3'
    bravo='valueB3'
    charlie='valueC3'
  }
) | ConvertTo-Json
```

Read more on [data structure in PowerShell](https://github.com/joetanx/setup/blob/main/web-request-notes.md#33-data-structure-in-powershell)

> [!Tip]
>
> If the array consists of a single row, PowerShell ignores the array and represents it as an object itself instead of an array of a single object
>
> An array of object … :
> 
> ```json
> [
>   {
>     <object>
>   }
> ]
> ```
>
> … and an object … :
> 
> ```json
> {
>   <object>
> }
> ```
>
> … are not the same
>
> When creating event data of a single row, add the below to add the `[]` brackets to make it an array:
>
> ```pwsh
> $body = "[
>   $body
> ]"
> ```

#### 3.2.1. Syslog example

```pwsh
$body = @(
  @{
    Computer='gitlab'
    EventTime='2025-06-29T23:50:06.5492801Z'
    Facility='auth'
    HostIP='192.168.17.21'
    HostName='gitlab'
    ProcessID=4594
    ProcessName='sshd'
    SeverityLevel='info'
    SyslogMessage='Invalid user doesnotexist from 192.168.17.20 port 57933'
    SourceSystem='LogsIngestionAPI'
  }
  @{
    Computer='gitlab'
    EventTime='2025-06-29T23:50:06.5740975Z'
    Facility='authpriv'
    HostIP='192.168.17.21'
    HostName='gitlab'
    ProcessID=4594
    ProcessName='sshd'
    SeverityLevel='notice'
    SyslogMessage='pam_unix(sshd:auth): check pass; user unknown'
    SourceSystem='LogsIngestionAPI'
  }
  @{
    Computer='gitlab'
    EventTime='2025-06-29T23:50:06.5740975Z'
    Facility='auth'
    HostIP='192.168.17.21'
    HostName='gitlab'
    ProcessID=4594
    ProcessName='sshd'
    SeverityLevel='notice'
    SyslogMessage='pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.17.20 '
    SourceSystem='LogsIngestionAPI'
  }
  @{
    Computer='gitlab'
    EventTime='2025-06-29T23:50:06.5740975Z'
    Facility='auth'
    HostIP='192.168.17.21'
    HostName='gitlab'
    ProcessID=4594
    ProcessName='sshd'
    SeverityLevel='info'
    SyslogMessage='Failed password for invalid user doesnotexist from 192.168.17.20 port 57933 ssh2'
    SourceSystem='LogsIngestionAPI'
  }
) | ConvertTo-Json
```

> [!Tip]
> 
> Syslog events have a table-like structure as the keys are uniform, it can also be represented as a table:
> 
> | SeverityLevel | ProcessID | HostName | EventTime                    | ProcessName | Computer | SyslogMessage                                                                                          | Facility | HostIP        | SourceSystem     |
> |---------------|-----------|----------|------------------------------|-------------|----------|--------------------------------------------------------------------------------------------------------|----------|---------------|------------------|
> | info          | 4594      | gitlab   | 2025-06-29T23:50:06.5492801Z | sshd        | gitlab   | Invalid user doesnotexist from 192.168.17.20 port 57933                                                | auth     | 192.168.17.21 | LogsIngestionAPI |
> | notice        | 4594      | gitlab   | 2025-06-29T23:50:06.5740975Z | sshd        | gitlab   | pam_unix(sshd:auth): check pass; user unknown                                                          | authpriv | 192.168.17.21 | LogsIngestionAPI |
> | notice        | 4594      | gitlab   | 2025-06-29T23:50:06.5740975Z | sshd        | gitlab   | pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.17.20  | auth     | 192.168.17.21 | LogsIngestionAPI |
> | info          | 4594      | gitlab   | 2025-06-29T23:50:06.5740975Z | sshd        | gitlab   | Failed password for invalid user doesnotexist from 192.168.17.20 port 57933 ssh2                       | auth     | 192.168.17.21 | LogsIngestionAPI |
> 
> If the data is available in CSV, `ConvertFrom-Csv` or `Import-Csv` can also be used to quickly import it
> 
> Read more on [representing uniform data in PowerShell](https://github.com/joetanx/setup/blob/main/web-request-notes.md#31-uniform-data)

#### 3.2.2. Windows event example

```pwsh
$body = @(
  @{
    EventData="<EventData>
<Data Name='SubjectUserSid'>S-1-5-18</Data>
<Data Name='SubjectUserName'>DC$</Data>
<Data Name='SubjectDomainName'>LAB</Data>
<Data Name='SubjectLogonId'>0x3e7</Data>
<Data Name='TargetUserSid'>S-1-0-0</Data>
<Data Name='TargetUserName'>doesnotexist</Data>
<Data Name='TargetDomainName'>LAB</Data>
<Data Name='Status'>0xc000006d</Data>
<Data Name='FailureReason'>%%2313</Data>
<Data Name='SubStatus'>0xc0000064</Data>
<Data Name='LogonType'>10</Data>
<Data Name='LogonProcessName'>User32 </Data>
<Data Name='AuthenticationPackageName'>Negotiate</Data>
<Data Name='WorkstationName'>DC</Data>
<Data Name='TransmittedServices'>-</Data>
<Data Name='LmPackageName'>-</Data>
<Data Name='KeyLength'>0</Data>
<Data Name='ProcessId'>0xc80</Data>
<Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data>
<Data Name='IpAddress'>0.0.0.0</Data>
<Data Name='IpPort'>0</Data>
</EventData>
"
    EventID=4625
    Version=0
    Level=0
    EventLevelName='LogAlways'
    Task=12544
    Opcode='0'
    Keywords='0x8010000000000000'
    Channel='Security'
    EventSourceName='Microsoft-Windows-Security-Auditing'
    Computer='DC.lab.vx'
    Activity='4625 - An account failed to log on.'
    SubjectUserSid='S-1-5-18'
    SubjectUserName='DC$'
    SubjectDomainName='LAB'
    SubjectLogonId='0x3e7'
    TargetUserSid='S-1-0-0'
    TargetUserName='doesnotexist'
    TargetDomainName='LAB'
    Status='0xc000006d'
    FailureReason='%%2313'
    SubStatus='0xc0000064'
    LogonType=10
    LogonTypeName='RemoteInteractive'
    LogonProcessName='User32 '
    AuthenticationPackageName='Negotiate'
    WorkstationName='DC'
    KeyLength=0
    ProcessId='0xc80'
    ProcessName='C:\Windows\System32\svchost.exe'
    IpAddress='0.0.0.0'
    IpPort=0
    EventRecordId='818'
    SystemThreadId=5980
    SystemProcessId=844
    SourceSystem='LogsIngestionAPI'
  }
  @{
    EventData="<EventData>
<Data Name='SubjectUserSid'>S-1-5-18</Data>
<Data Name='SubjectUserName'>DC$</Data>
<Data Name='SubjectDomainName'>LAB</Data>
<Data Name='SubjectLogonId'>0x3e7</Data>
<Data Name='NewProcessId'>0x1efc</Data>
<Data Name='NewProcessName'>C:\Windows\System32\svchost.exe</Data>
<Data Name='TokenElevationType'>%%1936</Data>
<Data Name='ProcessId'>0x344</Data>
<Data Name='CommandLine'>C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc</Data>
<Data Name='TargetUserSid'>S-1-0-0</Data>
<Data Name='TargetUserName'>-</Data>
<Data Name='TargetDomainName'>-</Data>
<Data Name='TargetLogonId'>0x0</Data>
<Data Name='ParentProcessName'>C:\Windows\System32\services.exe</Data>
<Data Name='MandatoryLabel'>S-1-16-16384</Data>
</EventData>
"
    EventID=4688
    Version=2
    Level=0
    EventLevelName='LogAlways'
    Task=13312
    Opcode='0'
    Keywords='0x8020000000000000'
    Channel='Security'
    EventSourceName='Microsoft-Windows-Security-Auditing'
    Computer='DC.lab.vx'
    Activity='4688 - A new process has been created.'
    SubjectUserSid='S-1-5-18'
    SubjectUserName='DC$'
    SubjectDomainName='LAB'
    SubjectLogonId='0x3e7'
    TargetUserSid='S-1-0-0'
    NewProcessId='0x1efc'
    NewProcessName='C:\Windows\System32\svchost.exe'
    TokenElevationType='%%1936'
    ProcessId='0x344'
    CommandLine='C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc'
    ParentProcessName='C:\Windows\System32\services.exe'
    MandatoryLabel='S-1-16-16384'
    EventRecordId='833'
    SystemThreadId=144
    SystemProcessId=4
    SourceSystem='LogsIngestionAPI'
  }
) | ConvertTo-Json
```

> [!Note]
>
> Unlike syslog, Windows events are non-uniform data, which may not be interpreted well when working with CSV
> 
> Read more on [representing non-uniform data in PowerShell](https://github.com/joetanx/setup/blob/main/web-request-notes.md#32-non-uniform-data)

### 3.3. Send the prepared data to logs ingestion API

Prepare the logs ingestion API URI:

```pwsh
$dce = 'https://<endpoint>.<region>.ingest.monitor.azure.com'
$dcr = '<dcr-immutable-id>'
$stream = 'Custom-SecurityEvent' #or 'Custom-Syslog'
$endpointuri = "$dce/dataCollectionRules/$dcr/streams/$stream`?api-version=2023-01-01"
```

Send the data:

```pwsh
Invoke-RestMethod $endpointuri -Method Post -Headers $headers -Body $body -ContentType 'application/json'
```

### 3.4. Example of ingested data

Syslog:

![image](https://github.com/user-attachments/assets/7d36be48-70a9-4e64-bb06-ae59140042d3)

Windows event:

![image](https://github.com/user-attachments/assets/7ae89bbf-65d2-4647-9fc1-873d53c09e04)
