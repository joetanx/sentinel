## 1. Azure Monitoring Agent

|OS|Machine Type|Installation|
|---|---|---|
|Windows|Azure VM|Automatically installed by Azure Windows VM agent (WindowsAzureGuestAgent.exe)|
|Linux|Azure VM|Automatically installed by Azure Linux VM agent (waagent)|
|Windows|Arc Machine|Automatically installed by AZCM agent|
|Linux|Arc Machine|**Manual installation required**|

### 1.1. Manually installing AMA on Linux

## 2. Data Collection Rules

### 2.1. Windows Security Events

### 2.2. Windows Forwarded Events

### 2.3. Microsoft Defender Antivirus Events

### 2.4. Linux Syslog

## 3. Other Events

High volume, recommend for data lake

### 3.1. DNS query



### 3.2. Firewall



### 3.3. VNet Flow Logs

To mention NSG flow logs deprecation

### 3.4. Key Vault



### 3.5. Application Gateway



## 4. Azure policy

https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#monitoring

|Azure Policy|Description|
|---|---|
|**Windows:**||
|Configure Windows **Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machines, virtual machine scale sets, and Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Windows **Virtual Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machines** to the specified Data Collection Rule or the specified Data Collection Endpoint. The list of locations and OS images are updated over time as support is increased.|
|Configure Windows **Virtual Machine Scale** Sets to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **virtual machine scale sets** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Windows **Arc Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Windows **Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Windows **Arc-enabled machines** to run Azure Monitor Agent|Automate the deployment of Azure Monitor Agent extension on your Windows **Arc-enabled machines** for collecting telemetry data from the guest OS. This policy will install the extension if the OS and region are supported and system-assigned managed identity is en|
|**Linux:**||
|Configure Linux **Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machines, virtual machine scale sets, and Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Virtual Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Virtual Machine Scale Sets** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **virtual machine scale sets** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Arc Machines** to be associated with a Data Collection Rule or a Data Collection Endpoint|Deploy Association to link Linux **Arc machines** to the specified Data Collection Rule or the specified Data Collection Endpoint.|
|Configure Linux **Arc-enabled machines** to run Azure Monitor Agent|Automate the deployment of Azure Monitor Agent extension on your Linux **Arc-enabled machines** for collecting telemetry data from the guest OS. This policy will install the extension if the region is supported. Learn more: https://aka.ms/AMAOverview.|
|**Others:**||
|Enable logging by category group for *** to log analytics||
