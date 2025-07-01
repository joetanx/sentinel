## 1. Windows Security Events

### 1.1. Process Execution Frequency Anomaly

This detection identifies anomalous spike in frequency of executions of sensitive processes which are often leveraged as attack vectors.

The query leverages KQL's built-in anomaly detection algorithms to find large deviations from baseline patterns.

Sudden increases in execution frequency of sensitive processes should be further investigated for malicious activity.

Tune the values from 1.5 to 3 in `series_decompose_anomalies` for further outliers or based on custom threshold values for score.

```kql
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 5;
// Configure the list with sensitive process names 
let ExeList = dynamic(["powershell.exe","cmd.exe","wmic.exe","psexec.exe","cacls.exe","rundll32.exe"]);
let TimeSeriesData =
SecurityEvent
| where EventID == 4688 | extend Process = tolower(Process)
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where Process in~ (ExeList)
| project TimeGenerated, Computer, AccountType, Account, Process
| make-series Total=count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by Process;
let TimeSeriesAlerts = materialize(TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 1.5, -1, 'linefit')
| mv-expand Total to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where anomalies > 0
| project Process, TimeGenerated, Total, baseline, anomalies, score
| where Total > TotalEventsThreshold);
let AnomalyHours = materialize(TimeSeriesAlerts  | where TimeGenerated > ago(2d) | project TimeGenerated);
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
SecurityEvent
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
| where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
| where EventID == 4688 | extend Process = tolower(Process)
| summarize CommandlineCount = count() by bin(TimeGenerated, 1h), Process, CommandLine, Computer, Account
) on Process, TimeGenerated
| project AnomalyHour = TimeGenerated, Computer, Account, Process, CommandLine, CommandlineCount, Total, baseline, anomalies, score
| extend timestamp = AnomalyHour, NTDomain = split(Account, '\\', 0)[0], Name = split(Account, '\\', 1)[0], HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
```

### 1.2. SecurityEvent - Multiple authentication failures followed by a success

Identifies accounts who have failed to logon to the domain multiple times in a row, followed by a successful authentication within a short time frame.

Multiple failed attempts followed by a success can be an indication of a brute force attempt or possible mis-configuration of a service account within an environment.

The lookback is set to 2h and the authentication window and threshold are set to 1h and 5, meaning we need to see a minimum of 5 failures followed by a success for an account within 1 hour to surface an alert.

```kql
let timeRange = 2h;
let authenticationWindow = 1h;
let authenticationThreshold = 5;
SecurityEvent
| where TimeGenerated > ago(timeRange)
| where EventID in (4624, 4625)
| where IpAddress != "-" and isnotempty(Account)
| extend Outcome = iff(EventID == 4624, "Success", "Failure")
// bin outcomes into 10 minute windows to reduce the volume of data
| summarize OutcomeCount=count() by bin(TimeGenerated, 10m), Account, IpAddress, Computer, Outcome
| project TimeGenerated, Account, IpAddress, Computer, Outcome, OutcomeCount
// sort ready for sessionizing - by account and time of the authentication outcome
| sort by TimeGenerated asc, Account, IpAddress, Computer, Outcome, OutcomeCount
| serialize
// sessionize into failure groupings until either the account changes or there is a success
| extend SessionStartedUtc = row_window_session(TimeGenerated, timeRange, authenticationWindow, Account != prev(Account) or prev(Outcome) == "Success")
// count the failures in each session
| summarize FailureCountBeforeSuccess=sumif(OutcomeCount, Outcome == "Failure"), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), make_list(Outcome, 128), make_set(Computer, 128), make_set(IpAddress, 128) by SessionStartedUtc, Account
// the session must not start with a success, and must end with one
| where array_index_of(list_Outcome, "Success") != 0
| where array_index_of(list_Outcome, "Success") == array_length(list_Outcome) - 1
| project-away SessionStartedUtc, list_Outcome
// where the number of failures before the success is above the threshold
| where FailureCountBeforeSuccess >= authenticationThreshold
// expand out ip and computer for customer entity assignment
| mv-expand set_IpAddress, set_Computer
| extend IpAddress = tostring(set_IpAddress), Computer = tostring(set_Computer)
| extend timestamp=StartTime, NTDomain = split(Account, '\\', 0)[0], Name = split(Account, '\\', 1)[0], HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
```

### 1.3. Excessive Windows Logon Failures

This query identifies user accounts which has over 50 Windows logon failures today and at least 33% of the count of logon failures over the previous 7 days.

```kql
let starttime = 8d;
let endtime = 1d;
let threshold = 0.333;
let countlimit = 50;
SecurityEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4625 and AccountType =~ "User"
| where IpAddress !in ("127.0.0.1", "::1")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), CountToday = count() by EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress, Process
| join kind=leftouter (
    SecurityEvent
    | where TimeGenerated between (ago(starttime) .. ago(endtime))
    | where EventID == 4625 and AccountType =~ "User"
    | where IpAddress !in ("127.0.0.1", "::1")
    | summarize CountPrev7day = count() by EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress
) on EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress
| where CountToday >= coalesce(CountPrev7day,0)*threshold and CountToday >= countlimit
//SubStatus Codes are detailed here - https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4625
| extend Reason = case(
SubStatus =~ '0xC000005E', 'There are currently no logon servers available to service the logon request.',
SubStatus =~ '0xC0000064', 'User logon with misspelled or bad user account',
SubStatus =~ '0xC000006A', 'User logon with misspelled or bad password',
SubStatus =~ '0xC000006D', 'Bad user name or password',
SubStatus =~ '0xC000006E', 'Unknown user name or bad password',
SubStatus =~ '0xC000006F', 'User logon outside authorized hours',
SubStatus =~ '0xC0000070', 'User logon from unauthorized workstation',
SubStatus =~ '0xC0000071', 'User logon with expired password',
SubStatus =~ '0xC0000072', 'User logon to account disabled by administrator',
SubStatus =~ '0xC00000DC', 'Indicates the Sam Server was in the wrong state to perform the desired operation',
SubStatus =~ '0xC0000133', 'Clocks between DC and other computer too far out of sync',
SubStatus =~ '0xC000015B', 'The user has not been granted the requested logon type (aka logon right) at this machine',
SubStatus =~ '0xC000018C', 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed',
SubStatus =~ '0xC0000192', 'An attempt was made to logon, but the Netlogon service was not started',
SubStatus =~ '0xC0000193', 'User logon with expired account',
SubStatus =~ '0xC0000224', 'User is required to change password at next logon',
SubStatus =~ '0xC0000225', 'Evidently a bug in Windows and not a risk',
SubStatus =~ '0xC0000234', 'User logon with account locked',
SubStatus =~ '0xC00002EE', 'Failure Reason: An Error occurred during Logon',
SubStatus =~ '0xC0000413', 'Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine',
strcat('Unknown reason substatus: ', SubStatus))
| extend WorkstationName = iff(WorkstationName == "-" or isempty(WorkstationName), Computer , WorkstationName)
| project StartTime, EndTime, EventID, Account, LogonTypeName, SubStatus, Reason, AccountType, Computer, WorkstationName, IpAddress, CountToday, CountPrev7day, Avg7Day = round(CountPrev7day*1.00/7,2), Process
| summarize StartTime = min(StartTime), EndTime = max(EndTime), Computer = make_set(Computer,128), IpAddressList = make_set(IpAddress,128), sum(CountToday), sum(CountPrev7day), avg(Avg7Day)
by EventID, Account, LogonTypeName, SubStatus, Reason, AccountType, WorkstationName, Process
| order by sum_CountToday desc nulls last
| extend timestamp = StartTime, NTDomain = tostring(split(Account, '\\', 0)[0]), Name = tostring(split(Account, '\\', 1)[0]), HostName = tostring(split(WorkstationName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(WorkstationName, '.'), 1, -1), '.'))
```

### 1.4. NRT Security Event log cleared

Checks for event id 1102 which indicates the security event log was cleared.

It uses Event Source Name "Microsoft-Windows-Eventlog" to avoid generating false positives from other sources, like AD FS servers for instance.

```kql
SecurityEvent
| where EventID == 1102 and EventSourceName == "Microsoft-Windows-Eventlog"
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), EventCount = count() by Computer, Account, EventID, Activity
| extend HostName = tostring(split(Computer, ".")[0]), DomainIndex = toint(indexof(Computer, '.'))
| extend HostNameDomain = iff(DomainIndex != -1, substring(Computer, DomainIndex + 1), Computer)
| extend AccountName = tostring(split(Account, @'\')[1]), AccountNTDomain = tostring(split(Account, @'\')[0])
```

## 2. Syslog

### 2.1. Failed logon attempts in authpriv

Identifies failed logon attempts from unknown users in Syslog authpriv logs.

The unknown user means the account that tried to log in isn't provisioned on the machine.

A few hits could indicate someone attempting to access a machine they aren't authorized to access. 

If there are many of hits, especially from outside your network, it could indicate a brute force attack. 

Default threshold for logon attempts is 15.

```kql
let threshold = 15;
// Below pulls messages from syslog-authpriv logs where there was an authentication failure with an unknown user.
// IP address of system attempting logon is also extracted from the SyslogMessage field. Some of these messages
// are aggregated.
Syslog
| where Facility =~ "authpriv"
| where SyslogMessage has "authentication failure" and SyslogMessage has " uid=0"
| extend RemoteIP = extract(@".*?rhost=([\d.]+).*?", 1,SyslogMessage)
| project TimeGenerated, Computer, ProcessName, HostIP, RemoteIP, ProcessID
| join kind=innerunique (
    // Below pulls messages from syslog-authpriv logs that show each instance an unknown user tried to logon. 
    Syslog 
    | where Facility =~ "authpriv"
    | where SyslogMessage has "user unknown"
    | project Computer, HostIP, ProcessID
    ) on Computer, HostIP, ProcessID
// Count the number of failed logon attempts by External IP and internal machine
| summarize FirstLogonAttempt = min(TimeGenerated), LatestLogonAttempt = max(TimeGenerated), TotalLogonAttempts = count() by Computer, HostIP, RemoteIP
// Calculate the time between first and last logon attempt (AttemptPeriodLength)
| extend TimeBetweenLogonAttempts = LatestLogonAttempt - FirstLogonAttempt
| where TotalLogonAttempts >= threshold
| project FirstLogonAttempt, LatestLogonAttempt, TimeBetweenLogonAttempts, TotalLogonAttempts, SourceAddress = RemoteIP, Computer,  HostIP
| sort by Computer asc nulls last
```

### 2.2. SSH - Potential Brute Force

Identifies an IP address that had 15 failed attempts to sign in via SSH in a 4 hour block during a 24 hour time period.

Please note that entity mapping for arrays is not supported, so when there is a single value in an array, we will pull that value from the array as a single string to populate the entity to support entity mapping features within Sentinel.

Additionally, if the array is multivalued, we will input a string to indicate this with a unique hash so that matching will not occur.

As an example - ComputerList is an array that we check for a single value and write that into the HostName field for use in the entity mapping within Sentinel.

```kql
let threshold = 15;
Syslog
| where ProcessName =~ "sshd"
| where SyslogMessage contains "Failed password for invalid user"
| parse kind=relaxed SyslogMessage with * "invalid user " user " from " ip " port" port " ssh2" *
// using distinct below as it has been seen that Syslog can duplicate entries depending on implementation
| distinct TimeGenerated, Computer, user, ip, port, SyslogMessage, _ResourceId
| summarize EventTimes = make_list(TimeGenerated), PerHourCount = count() by bin(TimeGenerated,4h), ip, Computer, user, _ResourceId
| where PerHourCount > threshold
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes)
| summarize StartTime = min(EventTimes), EndTime = max(EventTimes), UserList = make_set(user), ComputerList = make_set(Computer), ResourceIdList = make_set(_ResourceId), sum(PerHourCount) by IPAddress = ip
// bringing through single computer and user if array only has 1, otherwise, referencing the column and hashing the ComputerList or UserList so we don't get accidental entity matches when reviewing alerts
| extend HostName = iff(array_length(ComputerList) == 1, tostring(ComputerList[0]), strcat("SeeComputerListField","_", tostring(hash(tostring(ComputerList)))))
| extend Account = iff(array_length(ComputerList) == 1, tostring(UserList[0]), strcat("SeeUserListField","_", tostring(hash(tostring(UserList)))))
| extend ResourceId = iff(array_length(ResourceIdList) == 1, tostring(ResourceIdList[0]), strcat("SeeResourceIdListField","_", tostring(hash(tostring(ResourceIdList)))))
```
