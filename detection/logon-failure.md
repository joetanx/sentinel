## 1. Windows

### 1.1. Example event 4625: `An account failed to log on.`

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
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
- <EventData>
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
