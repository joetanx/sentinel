## 1. Windows and Linux

![](https://github.com/user-attachments/assets/09d0ea20-e3ed-4394-a069-8614b78e1989)

> [!Tip]
>
> Data collection rules (DCRs) work with Azure Monitor Agent (AMA) to collect events
>
> AMA is automatically installed by Azure VM agent or Azure Connected Machine agent when a machine is associated with a DCR

### 1.1. Windows Security Events

|Table|Data connector|Content hub solution|
|---|---|---|
|`SecurityEvents`|Windows Security Events via AMA|Windows Security Events|

![](https://github.com/user-attachments/assets/39420bda-b110-40e5-8783-5c0ea28462b2)

![](https://github.com/user-attachments/assets/51d31e1d-7b57-4fa1-9fc8-c2c666c8bdc8)

![](https://github.com/user-attachments/assets/8abe1611-94fe-4a31-b455-c7dfee747359)

> [!Tip]
>
> The xPathQueries used by the DCR for `Common` security events:
>
> ```
> "Security!*[System[(EventID=1) or (EventID=299) or (EventID=300) or (EventID=324) or (EventID=340) or (EventID=403) or (EventID=404) or (EventID=410) or (EventID=411) or (EventID=412) or (EventID=413) or (EventID=431) or (EventID=500) or (EventID=501) or (EventID=1100)]]",
> "Security!*[System[(EventID=1102) or (EventID=1107) or (EventID=1108) or (EventID=4608) or (EventID=4610) or (EventID=4611) or (EventID=4614) or (EventID=4622) or (EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or (EventID=4648) or (EventID=4649) or (EventID=4657)]]",
> "Security!*[System[(EventID=4661) or (EventID=4662) or (EventID=4663) or (EventID=4665) or (EventID=4666) or (EventID=4667) or (EventID=4688) or (EventID=4670) or (EventID=4672) or (EventID=4673) or (EventID=4674) or (EventID=4675) or (EventID=4689) or (EventID=4697) or (EventID=4700)]]",
> "Security!*[System[(EventID=4702) or (EventID=4704) or (EventID=4705) or (EventID=4716) or (EventID=4717) or (EventID=4718) or (EventID=4719) or (EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4727) or (EventID=4728)]]",
> "Security!*[System[(EventID=4729) or (EventID=4733) or (EventID=4732) or (EventID=4735) or (EventID=4737) or (EventID=4738) or (EventID=4739) or (EventID=4740) or (EventID=4742) or (EventID=4744) or (EventID=4745) or (EventID=4746) or (EventID=4750) or (EventID=4751) or (EventID=4752)]]",
> "Security!*[System[(EventID=4754) or (EventID=4755) or (EventID=4756) or (EventID=4757) or (EventID=4760) or (EventID=4761) or (EventID=4762) or (EventID=4764) or (EventID=4767) or (EventID=4768) or (EventID=4771) or (EventID=4774) or (EventID=4778) or (EventID=4779) or (EventID=4781)]]",
> "Security!*[System[(EventID=4793) or (EventID=4797) or (EventID=4798) or (EventID=4799) or (EventID=4800) or (EventID=4801) or (EventID=4802) or (EventID=4803) or (EventID=4825) or (EventID=4826) or (EventID=4870) or (EventID=4886) or (EventID=4887) or (EventID=4888) or (EventID=4893)]]",
> "Security!*[System[(EventID=4898) or (EventID=4902) or (EventID=4904) or (EventID=4905) or (EventID=4907) or (EventID=4931) or (EventID=4932) or (EventID=4933) or (EventID=4946) or (EventID=4948) or (EventID=4956) or (EventID=4985) or (EventID=5024) or (EventID=5033) or (EventID=5059)]]",
> "Security!*[System[(EventID=5136) or (EventID=5137) or (EventID=5140) or (EventID=5145) or (EventID=5632) or (EventID=6144) or (EventID=6145) or (EventID=6272) or (EventID=6273) or (EventID=6278) or (EventID=6416) or (EventID=6423) or (EventID=6424) or (EventID=8001) or (EventID=8002)]]",
> "Security!*[System[(EventID=8003) or (EventID=8004) or (EventID=8005) or (EventID=8006) or (EventID=8007) or (EventID=8222) or (EventID=26401) or (EventID=30004)]]",
> "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8001) or (EventID=8002) or (EventID=8003) or (EventID=8004)]]",
> "Microsoft-Windows-AppLocker/MSI and Script!*[System[(EventID=8005) or (EventID=8006) or (EventID=8007)]]"
> ```
>
> Read more on the [Windows security events collected by Sentinel](/collection/windows-security-events.md)

### 1.2. Microsoft Defender Antivirus Events

|Table|Data connector|Content hub solution|
|---|---|---|
|`SecurityEvents`|Windows Security Events via AMA|Windows Security Events|

> [!Note]
>
> [Microsoft Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
>
> |Event ID|Description|
> |---|---|
> |1116|The antimalware platform detected malware or other potentially unwanted software.|
> |1117|The antimalware platform performed an action to protect your system from malware or other potentially unwanted software.|

![](https://github.com/user-attachments/assets/bc473e6e-7f40-4200-8db9-3eed2b5ac6ec)

xPathQuery: `Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116) or (EventID=1117)]]`

![](https://github.com/user-attachments/assets/8115b2a8-99d6-4424-9dad-aa9043f1524f)

### 1.3. Windows Forwarded Events

|Table|Data connector|Content hub solution|
|---|---|---|
|`WindowsEvents`|Windows Forwarded Events|Windows Forwarded Events|

![](https://github.com/user-attachments/assets/144fbeab-889c-4893-b2b0-50bc323c040f)

![](https://github.com/user-attachments/assets/fdd88969-1e2c-436f-9e87-e6ba5e47ce95)

### 1.4. Linux Syslog

|Table|Data connector|Content hub solution|
|---|---|---|
|`Syslog`|Syslog via AMA|Syslog|

![](https://github.com/user-attachments/assets/09fe6786-a854-498a-a814-ab1591e62adc)

![](https://github.com/user-attachments/assets/bde254b0-16c6-4319-848c-0fc82d5f124c)

![](https://github.com/user-attachments/assets/884dd0b3-b086-4f29-bee5-84575f2031ba)

> [!Tip]
>
> What to collect for syslog?
>
> Recommended facilities to monitor:
>
> |Facility|Description|
> |---|---|
> |`LOG_AUTH` / `LOG_AUTHPRIV`|Tracks authentication and authorization events - crucial for detecting unauthorized access attempts.|
> |`LOG_DAEMON`|Covers system daemons like `sshd`, `cron`, and others - important for system health.|
> |`LOG_KERN`|Kernel messages - essential for catching low-level system issues.|
> |`LOG_CRON`|Scheduled task logs - useful for verifying job execution and spotting failures.|
> |`LOG_SYSLOG`|Messages generated by the syslog system itself - helps detect logging issues.|
> |`LOG_USER`|General user-level messages - good for catching unexpected user activity.|
>
> Monitor as required:
>
> |Facility|Description|
> |---|---|
> |`LOG_FTP`|If FTP is in use, monitor for file transfer activity and potential abuse.|
> |`LOG_NTP` / `LOG_CLOCK`|Time synchronization issues can wreak havoc for time sensitive applications - monitor if time accuracy is critical.|
> |`LOG_AUDIT` / `LOG_ALERT`|For systems with enhanced auditing or alerting mechanisms.|
> |`LOG_LOCAL0–7`|Often used by network devices (like routers and firewalls) or custom applications - monitor based on your specific setup.|
> |`LOG_MAIL`|If you're running a mail server, this helps track delivery issues and spam activity.|
> |`LOG_LPR`|For print server environments.|
> |`LOG_NEWS` / `LOG_UUCP`|Rarely used today unless you're running legacy systems.|

## 2. Azure policy

https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#monitoring

> [!Tip]
>
> The search in Azure policy matches for exact string
>
> e.g. searching for `associated with a Data Collection Rule` returns `Configure Windows Machines to be associated with a Data Collection Rule or a Data Collection Endpoint` as part of the results
>
> but searching for `windows machine data collection rule` returns nothing
>
> Setting `Category` to `Monitoring` in the filter helps to narrow down the search results

### 2.1. Windows and Linux machines

![](https://github.com/user-attachments/assets/34a4af92-fd35-4768-ad3b-6be21453fdb3)

#### 2.1.1. Windows:

##### Run AMA

|Policy Name|Description|
|---|---|
|Configure Windows virtual machines to run Azure Monitor Agent using system-assigned managed identity|Automate the deployment of Azure Monitor Agent extension on your Windows virtual machines for collecting telemetry data from the guest OS. This policy will install the extension if the OS and region are supported and system-assigned managed identity is enabled, and skip install otherwise.|
|Configure Windows virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication|Automate the deployment of Azure Monitor Agent extension on your Windows virtual machines for collecting telemetry data from the guest OS. This policy will install the extension and configure it to use the specified user-assigned managed identity if the OS and region are supported, and skip install otherwise.|
|Configure Windows **Arc-enabled machines** to run Azure Monitor Agent|Automate the deployment of Azure Monitor Agent extension on your Windows **Arc-enabled machines** for collecting telemetry data from the guest OS. This policy will install the extension if the OS and region are supported and system-assigned managed identity is enabled, and skip install otherwise.|

##### Associate with DCR/DCE

|Policy Name|Description|
|---|---|
|Configure Windows **Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machines, virtual machine scale sets, and Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Windows **Virtual Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machines** to the specified Data Collection Rule or the specified Data Collection Endpoint. The list of locations and OS images are updated over time as support is increased.|
|Configure Windows **Virtual Machine Scale** Sets to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machine scale sets** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Windows **Arc Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|

##### Assignment example

Select `Assign policy`:

![](https://github.com/user-attachments/assets/698bd7e8-8238-47f2-9099-266a1b1a055d)

Select the scope to assign this policy (management group, subscription or resource group):

![](https://github.com/user-attachments/assets/b432419e-bcd1-4194-b589-a527e562344a)

Enter the DCR resource Id:

> [!Tip]
>
> Go to the DCR resource and check `JSON View` for the resource Id:
>
> ![](https://github.com/user-attachments/assets/6666f786-f976-4054-abf0-0a60d5e7c6c7)

![](https://github.com/user-attachments/assets/64ce04e4-a8ef-4d67-ac00-f8018f1f58a0)

Check `Create a remediation task`:

![](https://github.com/user-attachments/assets/bbcced1a-690b-4776-9880-e0cde0b6f4df)

The policy scans for uncompliant resources and creates remediation task automatically:

![](https://github.com/user-attachments/assets/207e2fde-600a-4e3e-a17e-6cea38b295cc)

![](https://github.com/user-attachments/assets/aeea7a5e-f450-4fe0-ab4c-5f0e6d205735)

#### 2.1.2. Linux:

##### Run AMA

|Policy Name|Description|
|---|---|
|Configure Linux virtual machines to run Azure Monitor Agent with system-assigned managed identity-based authentication|Automate the deployment of Azure Monitor Agent extension on your Linux virtual machines for collecting telemetry data from the guest OS. This policy will install the extension if the OS and region are supported and system-assigned managed identity is enabled, and skip install otherwise.|
|Configure Linux virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication|Automate the deployment of Azure Monitor Agent extension on your Linux virtual machines for collecting telemetry data from the guest OS. This policy will install the extension and configure it to use the specified user-assigned managed identity if the OS and region are supported, and skip install otherwise.|
|Configure Linux **Arc-enabled machines** to run Azure Monitor Agent|Automate the deployment of Azure Monitor Agent extension on your Linux **Arc-enabled machines** for collecting telemetry data from the guest OS. This policy will install the extension if the region is supported.|

##### Associate with DCR/DCE

|Policy Name|Description|
|---|---|
|Configure Linux **Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machines, virtual machine scale sets, and Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Virtual Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Virtual Machine Scale Sets** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machine scale sets** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Arc Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|

##### Assignment example

Select `Assign policy`:

![](https://github.com/user-attachments/assets/718717fa-aa4b-419d-b40c-d6549d76a503)

Select the scope to assign this policy (management group, subscription or resource group):

![](https://github.com/user-attachments/assets/6473d3ac-a72a-4f7e-a2a3-bfbc5c1b1011)

Enter the DCR resource Id:

> [!Tip]
>
> Go to the DCR resource and check `JSON View` for the resource Id:
>
> ![](https://github.com/user-attachments/assets/b6fc74eb-7b57-4a9e-82a6-f9bf2da65d91)

![](https://github.com/user-attachments/assets/18450216-75f0-4ade-abc1-631dcf9a46f3)

Check `Create a remediation task`:

![](https://github.com/user-attachments/assets/61d9b2c2-6820-4679-9f6b-6d047fe4e3f4)

The policy scans for uncompliant resources and creates remediation task automatically:

![](https://github.com/user-attachments/assets/207e2fde-600a-4e3e-a17e-6cea38b295cc)

![](https://github.com/user-attachments/assets/edcdc071-d8fc-48ca-80e7-baeb24f23f08)

### 2.2. Azure services

|Policy Name|Description|
|---|---|
|Enable logging by category group for `<service>` to `[Event Hub\|Log Analyics\|Storage]`|Resource logs should be enabled to track activities and events that take place on your resources and give you visibility and insights into any changes that occur. This policy deploys a diagnostic setting using a category group to route logs to `[Event Hub\|Log Analyics\|Storage]` for `<service>`.|

![](https://github.com/user-attachments/assets/17a3c7d8-89da-4fb9-aacb-9eb57c7d84ee)

## 3. Other Events

### 3.1. [Secure and view DNS traffic](https://learn.microsoft.com/en-us/azure/dns/dns-traffic-log-how-to)

#### 3.1.1. Create DNS security policy

![](https://github.com/user-attachments/assets/7d4fb0f4-7415-46dd-9ea2-0f4d9436a591)

Select the virtual networks that the DNS security policy should apply to:

![](https://github.com/user-attachments/assets/c1b35daf-ba4d-47ae-9094-319cf1d0cbb5)

From the [Nov-2025 announcement](https://techcommunity.microsoft.com/blog/azurenetworkingblog/announcing-azure-dns-security-policy-with-threat-intelligence-feed-general-avail/4470183), Azure provides the _Azure DNS Threat Intel feed_ that tracks known malicious domain names:

![](https://github.com/user-attachments/assets/30d5f5f8-11ba-4961-8ae3-d5e66eb37459)

#### 3.1.2. Configure diagnostic settings to log to Sentinel

DNS security policy → Monitoring → Diagnostic settings → Add diagnostic setting:

![](https://github.com/user-attachments/assets/27ec3358-63d2-4b5d-92f5-be87194c873e)

Select destination Sentinel workspace and save:

![](https://github.com/user-attachments/assets/178ddd85-6668-40cc-97de-b9fb54c74ddf)

#### 3.1.3. Blocked DNS query example

![](https://github.com/user-attachments/assets/bdf29d28-ed4e-4ed8-91b7-66f6c2be2498)

```kql
DNSQueryLogs
| where ResolverPolicyDomainListId == 'Azure DNS Threat Intel'
```

![](https://github.com/user-attachments/assets/bd7353ea-55d2-485b-b093-f92614f18317)

> [!Warning]
>
> DNS query logs are highly verbose and can incur large ingestion and retention costs
>
> Check the `DNSQueryLogs` table size and consider retaining in Sentinel Data Lake to optimize cost
>
> ```kql
> DNSQueryLogs
> | where TimeGenerated > ago(30d)
> | summarize
>     RowCount = count(),
>     Size_MB = sum(estimate_data_size(*)) / 1024 / 1024
> ```
>
> ![](https://github.com/user-attachments/assets/7cf3dbf4-6011-4ce2-84c8-a82f7d5bb88d)

### 3.2. Firewall

Firewall → Monitoring → Diagnostic settings → Add diagnostic setting:

![](https://github.com/user-attachments/assets/fcc0b321-8d74-41df-8b04-77a67ed870cf)

Select destination Sentinel workspace and save:

![](https://github.com/user-attachments/assets/6a16e061-d819-4537-9c76-7af693069d94)

> [!Warning]
>
> Firewall logs are highly verbose and can incur large ingestion and retention costs
>
> Check the `AzureDiagnostics` table size and consider retaining in Sentinel Data Lake to optimize cost
>
> ```kql
> DNSQueryLogs
> | where TimeGenerated > ago(30d) and ResourceType == "AZUREFIREWALLS"
> | summarize
>     RowCount = count(),
>     Size_MB = sum(estimate_data_size(*)) / 1024 / 1024
> ```
>
> ![](https://github.com/user-attachments/assets/0a3d2e11-8725-4abf-9d8d-47444b2deddc)

### 3.3. Virtual network flow log

#### 3.3.1. Create flow log

![](https://github.com/user-attachments/assets/9db1d08b-245f-43f9-b9a1-5d978d1fd106)

VNet flow logs require a storage account:

![](https://github.com/user-attachments/assets/3d307077-1ce8-4bed-a3be-d018ce89475d)

Target resource can be:
- Virtual network
- Subnet
- Network interface

![](https://github.com/user-attachments/assets/437be706-3cab-4420-a099-978ca8e0c567)

Enable traffic analytics to send flow logs to Sentinel:

> [!Note]
>
> There are only 2 options for Traffic analytics processing interval:
> - Every 1 hour
> - Every 10 mins

![](https://github.com/user-attachments/assets/88b1397c-83a1-4d46-8db7-308bf17324bf)

> [!Tip]
>
> The subscription where the Sentinel workspace resides needs to be registered with provider `Microsoft.Network`, the error below occurs if it is not registered:
>
> ```
> {
>     "status": "Failed",
>     "error": {
>         "code": "CannotGetWorkspace",
>         "message": "Could not get Log Analytics Workspace resource /subscriptions/b70fcef1-9e03-4184-9321-4266c7b469ab/resourceGroups/delta-security-rg/providers/Microsoft.OperationalInsights/workspaces/delta-soc. If workspace exists, check if its subscription b70fcef1-9e03-4184-9321-4266c7b469ab is registered with provider Microsoft.Network. You can use powershell cmdlet to do this: Register-AzResourceProvider -ProviderNamespace Microsoft.Network. Please retry operation after.",
>         "details": []
>     }
> }
> ```
>
> Use Azure PowerShell to register the subscription:
>
>  ![](https://github.com/user-attachments/assets/f2a91d28-fe47-4bbf-9718-a40ccb6b8103)

### 3.4. Key Vault



### 3.5. Application Gateway


