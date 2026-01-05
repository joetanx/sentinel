## 1. Windows

### 1.1. Example event 4625: `An account failed to log on.`

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
    <EventID>4625</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12544</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8010000000000000</Keywords> 
    <TimeCreated SystemTime="2025-12-31T01:32:59.9278361Z" /> 
    <EventRecordID>21914</EventRecordID> 
    <Correlation ActivityID="{38d9161f-6cda-46bb-a720-a464a964a890}" /> 
    <Execution ProcessID="856" ThreadID="6228" /> 
    <Channel>Security</Channel> 
    <Computer>delta-vm-winsvr</Computer> 
    <Security /> 
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data> 
    <Data Name="SubjectUserName">-</Data> 
    <Data Name="SubjectDomainName">-</Data> 
    <Data Name="SubjectLogonId">0x0</Data> 
    <Data Name="TargetUserSid">S-1-0-0</Data> 
    <Data Name="TargetUserName">azureuser</Data> 
    <Data Name="TargetDomainName">-</Data> 
    <Data Name="Status">0xc000006d</Data> 
    <Data Name="FailureReason">%%2313</Data> 
    <Data Name="SubStatus">0xc000006a</Data> 
    <Data Name="LogonType">3</Data> 
    <Data Name="LogonProcessName">NtLmSsp</Data> 
    <Data Name="AuthenticationPackageName">NTLM</Data> 
    <Data Name="WorkstationName">vm000005</Data> 
    <Data Name="TransmittedServices">-</Data> 
    <Data Name="LmPackageName">-</Data> 
    <Data Name="KeyLength">0</Data> 
    <Data Name="ProcessId">0x0</Data> 
    <Data Name="ProcessName">-</Data> 
    <Data Name="IpAddress">10.10.0.6</Data> 
    <Data Name="IpPort">0</Data> 
  </EventData>
</Event>
```

### 1.2. KQL Query

```kql
let lookback = 12h;
let isCurrentHourAnomalous = SecurityEvent
| where EventID == 4625 and TimeGenerated >= ago(lookback)
| make-series FailedLogons = count() on TimeGenerated from ago(lookback) to now() step 1h
| extend (anomalous, score, baseline) = series_decompose_anomalies(FailedLogons)
| mv-expand TimeGenerated to typeof(datetime), FailedLogons, anomalous, score, baseline
| where anomalous == 1 and TimeGenerated >= ago(1h);
SecurityEvent
| where isnotempty(toscalar(isCurrentHourAnomalous)) and EventID == 4625 and TimeGenerated >= ago(1h)
```

![](https://github.com/user-attachments/assets/9aac656a-f7f2-4394-addf-c9bc6daa6b11)

### 1.3. Detection Rule

**Title:** _Anomalous Windows Authentication Failure Activity_

**Description:**

> An abnormal volume of Windows 4625 failed logon events is identified with look back over the past 12 hours.
>
> Using series_decompose_anomalies() with default values:
> - threshold=1.5 (for detecting mild or stronger anomalies)
> - seasonality=-1 (autodetect seasonality using series_periods_detect)
> - trend=linefit (extract trend component using linear regression)

![](https://github.com/user-attachments/assets/843ff925-091f-459b-9bf6-9b861f133123)

![](https://github.com/user-attachments/assets/43430d9b-6bcb-4c0f-9272-4b4765373d59)

## 2. Linux

### 2.1. Example sshd logon failures

Invalid user:

```
Dec 31 08:09:06 delta-vm-ubuntu sshd[970]: Invalid user doesnotexist from 10.0.0.4 port 62686
Dec 31 08:09:08 delta-vm-ubuntu sshd[970]: pam_unix(sshd:auth): check pass; user unknown
Dec 31 08:09:08 delta-vm-ubuntu sshd[970]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.4
Dec 31 08:09:10 delta-vm-ubuntu sshd[970]: Failed password for invalid user doesnotexist from 10.0.0.4 port 62686 ssh2
Dec 31 08:09:12 delta-vm-ubuntu sshd[970]: pam_unix(sshd:auth): check pass; user unknown
Dec 31 08:09:14 delta-vm-ubuntu sshd[970]: Failed password for invalid user doesnotexist from 10.0.0.4 port 62686 ssh2
Dec 31 08:09:17 delta-vm-ubuntu sshd[970]: pam_unix(sshd:auth): check pass; user unknown
Dec 31 08:09:18 delta-vm-ubuntu sshd[970]: Failed password for invalid user doesnotexist from 10.0.0.4 port 62686 ssh2
Dec 31 08:09:18 delta-vm-ubuntu sshd[970]: Connection reset by invalid user doesnotexist 10.0.0.4 port 62686 [preauth]
Dec 31 08:09:18 delta-vm-ubuntu sshd[970]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.4
```

Known user, wrong password:

```
Dec 31 08:10:12 delta-vm-ubuntu sshd[982]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.4  user=logon
Dec 31 08:10:13 delta-vm-ubuntu sshd[982]: Failed password for logon from 10.0.0.4 port 62687 ssh2
Dec 31 08:10:17 delta-vm-ubuntu sshd[982]: Failed password for logon from 10.0.0.4 port 62687 ssh2
Dec 31 08:10:21 delta-vm-ubuntu sshd[982]: Failed password for logon from 10.0.0.4 port 62687 ssh2
Dec 31 08:10:22 delta-vm-ubuntu sshd[982]: Connection reset by authenticating user logon 10.0.0.4 port 62687 [preauth]
Dec 31 08:10:22 delta-vm-ubuntu sshd[982]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.4  user=logon
```

### 2.2. KQL Query

```kql
let lookback = 12h;
let isCurrentHourAnomalous = Syslog
| where Facility in ('auth', 'authpriv') and ProcessName =~ 'sshd' and SyslogMessage contains 'failed password' and TimeGenerated >= ago(lookback)
| make-series FailedLogons = count() on TimeGenerated from ago(lookback) to now() step 1h
| extend (anomalous, score, baseline) = series_decompose_anomalies(FailedLogons)
| mv-expand TimeGenerated to typeof(datetime), FailedLogons, anomalous, score, baseline
| where anomalous == 1 and TimeGenerated >= ago(1h);
Syslog
| where isnotempty(toscalar(isCurrentHourAnomalous)) and Facility in ('auth', 'authpriv') and ProcessName =~ 'sshd' and SyslogMessage contains 'failed password' and TimeGenerated >= ago(1h)
| extend User = extract(@"Failed password for (?:invalid user |)(\S+)", 1, SyslogMessage)
| extend RemoteIP = extract(@"from (\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
```

![](https://github.com/user-attachments/assets/87da8aa6-ff1f-4f08-9cdd-bd8ec1e9f98d)

### 2.3. Detection Rule

**Title:** _Anomalous Linux Authentication Failure Activity_

**Description:**

> An abnormal volume of Linux failed logon password events is identified with look back over the past 12 hours.
>
> Using series_decompose_anomalies() with default values:
> - threshold=1.5 (for detecting mild or stronger anomalies)
> - seasonality=-1 (autodetect seasonality using series_periods_detect)
> - trend=linefit (extract trend component using linear regression)

![](https://github.com/user-attachments/assets/42ce50a3-1dce-48a8-9aca-f7670c6cce92)

![](https://github.com/user-attachments/assets/83785c69-3c4d-4d05-8834-5c4db031bebf)

## 3. Incidents and alerts

![](https://github.com/user-attachments/assets/89ae9dce-1d52-4db0-9649-940ddcd18759)

![](https://github.com/user-attachments/assets/553795ad-01f7-46d9-8148-5a997e5866b7)
