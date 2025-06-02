## 1. Provision Sentinel workspace

### 1.1. Create log analytics workspace

![image](https://github.com/user-attachments/assets/e2e98189-ce6c-4398-b05d-285a93ca5740)

### 1.2. Add Sentinel to the LAW

![image](https://github.com/user-attachments/assets/634941ff-871e-4fdf-ad39-46443fc3f039)

## 2. Essential Sentinel solutions

Install Sentinel solutions: left pane → Content management → Content hub

|Solution||
|---|---|
|Azure Activity|![image](https://github.com/user-attachments/assets/13706142-b82a-435a-8db9-6ca56762005c)|
|Defender for Cloud|![image](https://github.com/user-attachments/assets/5bc87714-192e-4355-bc17-064bf117081b)|
|Defender XDR|![image](https://github.com/user-attachments/assets/9b53ad74-3b19-4cde-8dc1-504c2350c441)|
|Entra ID|![image](https://github.com/user-attachments/assets/ecca831e-2d19-4716-b91e-e83cdae1c0df)|
|Security Threat Essentials|![image](https://github.com/user-attachments/assets/27376d78-0b58-4cd7-a818-584106eaedcc)|
|Sentinel SOAR Essentials|![image](https://github.com/user-attachments/assets/35ca6fbd-d58e-4d85-ad8d-b4ec3c1ac540)|
|SOC Handbook|![image](https://github.com/user-attachments/assets/ae730724-5078-48d9-b399-459192284b9b)|
|Threat Intelligence|![image](https://github.com/user-attachments/assets/02a7f848-b55e-447a-9962-81676ff8923b)|
|UEBA Essentials|![image](https://github.com/user-attachments/assets/9d9a441e-5c30-42db-b2b5-66a16e09a20a)|
|VirusTotal|![image](https://github.com/user-attachments/assets/47b36ab1-bd96-4f91-9242-465aabf16fb8)|
|Windows Security Events|![image](https://github.com/user-attachments/assets/bb179103-1e4d-4d0d-9bac-22033ea747e1)|
|Windows Forwarded Events|![image](https://github.com/user-attachments/assets/e0dbbec8-c6c3-4471-95d0-24e41fb2ffb4)|
|Common Event Format|![image](https://github.com/user-attachments/assets/c1cad278-2634-4628-b104-553c614c1e4e)|
|Syslog|![image](https://github.com/user-attachments/assets/024c1f44-769b-4ac9-946f-7785424c2844)|

## 3. Ingestion

Configure data connectors: left pane → Configuration → Data connectors → select the connector → Open connector page

> [!Tip]
>
> The connector `Status` changes to `Connected` after it's configured
>
> The `Last Log Received` timestamp and `Data received` timeline would show if there is actually data coming in

### 3.1. Windows Security Events via AMA

Ref: https://learn.microsoft.com/en-us/azure/sentinel/connect-services-windows-based

#### 3.1.1. Create data collection rule

![image](https://github.com/user-attachments/assets/0f738732-e94a-4db3-b8e8-e951b7163503)

Select the resources that the DCR will cover:

> [!Note]
>
> At the end of this process, the Azure Monitor Agent will be installed on any selected machines that don't already have it installed.

![image](https://github.com/user-attachments/assets/8afc7084-a162-41ad-b456-2d3366dc09d4)

Select events to stream:

> [!Tip]
>
> Read more on the [Windows security events collected by Sentinel](/windows-security-events.md)

![image](https://github.com/user-attachments/assets/ea3e9ea8-0eb4-49b6-aceb-810e966834c4)

#### 3.1.2. Results

![image](https://github.com/user-attachments/assets/21aba00d-3b21-4ee9-9f4e-d8f20609e453)

![image](https://github.com/user-attachments/assets/fac1ff37-840e-4d74-9e03-53423f02c3b5)

### 3.2. Windows Forwarded Events

#### 3.2.1. Create data collection rule

![image](https://github.com/user-attachments/assets/51214df4-5d93-4e57-ae85-d151ade8e4ab)

Select the Windows events collector:

![image](https://github.com/user-attachments/assets/fb06bf25-04c7-4167-b0ef-0affbd27c47f)

Select events to stream:

![image](https://github.com/user-attachments/assets/f77197b2-3a8d-45a9-8e9c-cfd2a1689f07)

#### 3.2.2. Results

![image](https://github.com/user-attachments/assets/cb73641d-3363-4163-9c04-6fae11dcaca0)

### 3.3. Syslog via AMA

Ref: https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama

#### 3.3.1. Install AMA on Linux machines

```sh
curl -sLO https://github.com/Azure/Azure-Sentinel/raw/refs/heads/master/DataConnectors/Syslog/Forwarder_AMA_installer.py
python Forwarder_AMA_installer.py
```

![image](https://github.com/user-attachments/assets/8bfd847e-143a-4963-93a0-dd1c21286ba2)

![image](https://github.com/user-attachments/assets/5d55e148-25a7-42c0-9443-c540ff95bac2)

#### 3.3.2. Create data collection rule

![image](https://github.com/user-attachments/assets/8ad7f35c-a2b1-4fb9-bff8-1a8982221f51)

Select the resources that the DCR will cover:

![image](https://github.com/user-attachments/assets/bb5b4422-b724-4687-98c8-f30de1f79330)

Select log facilities and levels to collect:

![image](https://github.com/user-attachments/assets/218b1602-3da0-4557-8ade-2bebb530dcf6)

#### 3.3.3. Results

![image](https://github.com/user-attachments/assets/423999e2-91dc-467a-b1d6-71d2c5404e56)

Check AMA status `systemctl status azuremonitor*`:

![image](https://github.com/user-attachments/assets/dd272461-8668-45ce-b551-c1ce5e6cae7d)
