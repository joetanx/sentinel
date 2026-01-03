## 0. Overview

Windows event forwarding uses WinRM protocol, which supports:
- Kerberos authentication in same-domain environments
- Certificate authentication in separate domains or WORKGROUP environments

## 1. Setup collector and forwarder certificates

Requirements:

|Machine|Requirement|
|---|---|
|Collector|This is the service certificate used for the WinRM HTTPS listener.<br>The FQDN or IP that the forwarders would be using to connect to the collector should be in the subject CN or included in the SANs of the certificate.|
|Forwarder|This the client certificate used by `NETWORK SERVICE` to authenticate the machine connecting to the collector.<br>The forwarder's machine name should be in the subject CN or included in the SANs of the certificate.|

This example uses the self-signed certificate chain from [lab-certs](https://github.com/joetanx/lab-certs) repository

|Certificate|Thumbprint|
|---|---|
|Lab Root|`E9AEA1BA21DA8352AA3999AE94891466CD761958`|
|Lab Issuer|`476F0ABF52FD56722B9C9A833144D9ABB7F55CE9`|

> [!Note]
>
> The intermediate CA `Lab Issuer` is used to generate the certificates
>
> The certificate thumbprint of the intermediate CA, **not root CA**, would be use in both collector and forwarder configurations

> [!Tip]
>
> It is also possible to use the `New-SelfSignedCertificate` to generate direct self-signed certificates without any chain hierarchy
>
> In this case, the certificates between collector and forwarder would need to be cross-trusted (i.e. imported in the the Root store), and the certificate thumbprints would need to be cross-configure in the respective configurations

### 1.1. Download and importthe Lab Issuer package

Perform this on both the collector and forwarder machines

```pwsh
Invoke-WebRequest https://github.com/joetanx/lab-certs/raw/refs/heads/main/ca/lab_issuer.pfx -OutFile lab_issuer.pfx
certutil -csp "Microsoft Software Key Storage Provider" -p lab -importPFX lab_issuer.pfx
```

### 1.2. Generate the certificates

Below commands:
- uses the imported Lab Issuer to sign the certificates (`-Signer cert:\LocalMachine\My\476F0ABF52FD56722B9C9A833144D9ABB7F55CE9`)
- creates certificates with 25 years validity from 2025 to 2050 (yes, it's overkill)

#### Collector

```pwsh
New-SelfSignedCertificate -KeyAlgorithm nistP384 -Subject 'O=vx Lab, CN=Windows Event Collector' `
-TextExtension @("2.5.29.17={text}DNS=dc&DNS=dc.lab.vx&IPAddress=192.168.17.20") -CertStoreLocation cert:\LocalMachine\My `
-Signer cert:\LocalMachine\My\476F0ABF52FD56722B9C9A833144D9ABB7F55CE9 `
-NotBefore ([datetime]::parseexact('01-Jan-2025','dd-MMM-yyyy',$null)) -NotAfter ([datetime]::parseexact('01-Jan-2050','dd-MMM-yyyy',$null))
```

- The `-TextExtension` option is used with OID `2.5.29.17` to specifiy entries for the collector's machine name, FQDN and IP address in the SAN
- It is helpful to include all names and IP addresses that forwarders would use to connect to the collector to minimize SSL certificate errors

#### Forwarder

```pwsh
New-SelfSignedCertificate -KeyAlgorithm nistP384 -Subject 'O=vx Lab, CN=Windows Event Client' `
-DnsName $(hostname) -CertStoreLocation cert:\LocalMachine\My `
-Signer cert:\LocalMachine\My\476F0ABF52FD56722B9C9A833144D9ABB7F55CE9 `
-NotBefore ([datetime]::parseexact('01-Jan-2020','dd-MMM-yyyy',$null)) -NotAfter ([datetime]::parseexact('01-Jan-2050','dd-MMM-yyyy',$null))
```

The forwarder certificate is simpler with just using the `-DnsName` to put the forwarder's machine name in the SAN, this option can only be used to specify a single DNS SAN entry

## 2. Configure WinRM on the collector

### 2.1. Enable certificate authentication method for WinRM

#### Configure

Powershell:

```pwsh
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
```

Or command prompt:

```cmd
winrm s winrm/config/service/auth '@{Certificate="true"}'
```

#### Verify

Powershell:

```pwsh
Get-WSManInstance -ResourceURI winrm/config/service/auth
```

Or powershell (another way):

```pwsh
Get-ChildItem -Path WSMan:\localhost\Service\Auth
```

Or command prompt:

```cmd
winrm g winrm/config/service/auth
```

<details><summary>Example results</summary>

```pwsh
PS C:\Users\Administrator> Get-ChildItem -Path WSMan:\localhost\Service\Auth


   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Service\Auth

Type            Name                           SourceOfValue   Value
----            ----                           -------------   -----
System.String   Basic                                          false
System.String   Kerberos                                       true
System.String   Negotiate                                      true
System.String   Certificate                                    true
System.String   CredSSP                                        false
System.String   CbtHardeningLevel                              Relaxed
```

</details>

### 2.2. Configure firewall rule for WinRM over HTTPS

Powershell:

```pwsh
New-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' -Direction Inbound -Program System -Protocol TCP -LocalPort 5986 -Action Allow -Group 'Windows Remote Management'
```

Or command prompt:

```cmd
netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in program=System protocol=tcp localport=5986 action=allow
```

### 2.3. Configure HTTPS listner

#### Configure

```pwsh
$cert = (Get-ChildItem cert:\LocalMachine\My | where {$_.subject -eq 'O=vx Lab, CN=Windows Event Collector'})
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
```

#### Verify or troubleshooting commands

Enumerate all listeners:

```pwsh
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
```

Get HTTPS listener details:

```pwsh
Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address='*';Transport='HTTPS'}
```

Remove HTTPS listener:

```pwsh
Remove-WSManInstance winrm/config/Listener -SelectorSet @{Address='*';Transport='HTTPS'}
```

<details><summary>Example results</summary>

```pwsh
PS C:\Users\Administrator> $cert = (Get-ChildItem cert:\LocalMachine\My | where {$_.subject -eq 'O=vx Lab, CN=Windows Event Collector'})
PS C:\Users\Administrator> New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force


   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Listener

Type            Keys                                Name
----            ----                                ----
Container       {Transport=HTTPS, Address=*}        Listener_1305953032


PS C:\Users\Administrator> Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate


cfg                   : http://schemas.microsoft.com/wbem/wsman/1/config/listener
xsi                   : http://www.w3.org/2001/XMLSchema-instance
lang                  : en-US
Address               : *
Transport             : HTTP
Port                  : 5985
Hostname              :
Enabled               : true
URLPrefix             : wsman
CertificateThumbprint :
ListeningOn           : {127.0.0.1, 192.168.17.20, ::1}

cfg                   : http://schemas.microsoft.com/wbem/wsman/1/config/listener
xsi                   : http://www.w3.org/2001/XMLSchema-instance
lang                  : en-US
Address               : *
Transport             : HTTPS
Port                  : 5986
Hostname              :
Enabled               : true
URLPrefix             : wsman
CertificateThumbprint : BFCF07C1164CC5B2194225C29A6651F279285A9E
ListeningOn           : {127.0.0.1, 192.168.17.20, ::1}
```

</details>

### 2.4. OPTIONAL - Testing WinRM connnection to the collector

#### 2.4.1. Create test user

Domain user:

```cmd
dsadd user "cn=Windows Event Collector,ou=Services,dc=lab,dc=vx" -samid wecsvc -upn wecsvc@lab.vx -email wecsvc@lab.vx -display "Windows Event Collector" -disabled no -pwd Micro123 -pwdneverexpires yes
dsmod group "CN=Remote Management Users,CN=Builtin,DC=lab,DC=vx" -addmbr "CN=Windows Event Collector,ou=Services,dc=lab,dc=vx"
```

Local user:

```cmd
net user wecsvc Micro123 /add
net localgroup "Remote Management Users" wecsvc /add
```

#### 2.4.2. Configure certificate mapping

##### Configure

```pwsh
$issuer = (Get-ChildItem cert:\LocalMachine\CA | where {$_.subject -eq 'CN=Lab Issuer'})
New-Item -Path WSMan:\localhost\ClientCertificate  -Subject * -URI * -Issuer $issuer.Thumbprint -Credential (Get-Credential) -Force
```

##### Verify

```pwsh
Get-ChildItem WSMan:\localhost\ClientCertificate
```

<details><summary>Example results</summary>

```pwsh
PS C:\Users\Administrator> $issuer = (Get-ChildItem cert:\LocalMachine\CA | where {$_.subject -eq 'CN=Lab Issuer'})
PS C:\Users\Administrator> New-Item -Path WSMan:\localhost\ClientCertificate  -Subject * -URI * -Issuer $issuer.Thumbprint -Credential (Get-Credential) -Force

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential


   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\ClientCertificate

Type            Keys                                Name
----            ----                                ----
Container       {URI=*, Issuer=476F0ABF52FD56722... ClientCertificate_524521784
```

![image](https://github.com/user-attachments/assets/0d3e5cbe-9e77-45aa-b77e-10f4d61ddba5)

</details>

#### 2.4.3. Test connection

```pwsh
$cert = (Get-ChildItem cert:\LocalMachine\My | where {$_.subject -eq 'O=vx Lab, CN=Windows Event Client'})
```

#### Connect WinRM with basic authentication

- For troubleshooting if the WinRM service is working/accessible
- Basic authentication should be enabled with `Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true` for this to work

```pwsh
Enter-PSSession -ComputerName 192.168.17.20 -UseSSL -Credential (Get-Credential)
```

#### Connect WinRM with certificate authentication

```pwsh
Enter-PSSession -ComputerName 192.168.17.20 -UseSSL -CertificateThumbprint $cert.Thumbprint
```

#### Invoke-command with certificate authentication

```pwsh
Invoke-Command -ComputerName 192.168.17.20 -UseSSL -CertificateThumbprint $cert.Thumbprint -ScriptBlock {1}
```

<details><summary>Example results</summary>

```pwsh
PS C:\Users\Administrator> $cert = (Get-ChildItem cert:\LocalMachine\My | where {$_.subject -eq 'O=vx Lab, CN=Windows Event Client'})
PS C:\Users\Administrator> Enter-PSSession -ComputerName 192.168.17.20 -UseSSL -CertificateThumbprint $cert.Thumbprint
[192.168.17.20]: PS C:\Users\wecsvc\Documents> whoami
lab\wecsvc
[192.168.17.20]: PS C:\Users\wecsvc\Documents> hostname
DC
```

</details>

#### 2.4.4. Clean-up test user

Domain user:

```cmd
dsrm -noprompt "cn=Windows Event Collector,ou=Services,dc=lab,dc=vx"
```

Local user:

```cmd
net user wecsvc /delete
```

## 3. Grant permissions to `NETWORK SERVICE` on event log

> [!Note]
>
> Perform on both collector and forwarder machines

Domain user:

```cmd
dsmod group "CN=Event Log Readers,CN=Builtin,DC=lab,DC=vx" -addmbr "CN=S-1-5-20,CN=ForeignSecurityPrincipals,DC=lab,DC=vx"
```

Local user:

```cmd
net localgroup "Event Log Readers" "NETWORK SERVICE" /add
```

> [!Note]
>
> In some cases, `NETWORK SERVICE` may need to be added to `Manage auditing and security log` user rights assignment
>
> Location: Group Policy Editer → Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Manage auditing and security log
>
> ![image](https://github.com/user-attachments/assets/7687d8a2-54d4-435b-b908-f4e16b79974d)

## 4. Configure events subscriber on the collector

### 4.1. Configure Windows Event Collector service

```cmd
wecutil qc /q
```

### 4.2. Create subscription

Event Viewer → Subscriptions → Create Subscription

![image](https://github.com/user-attachments/assets/62bb7b94-754b-40f2-a1b6-e0b4a38d70f2)

|Field|Entry|
|---|---|
|Subscription name|Enter a name|
|Destination Log|Select a destination, usually `Forwarded Events`|
|Subscription type and source computers|Source computer initiated|

![image](https://github.com/user-attachments/assets/dd710d97-b3a1-4594-bcad-02e61664e814)

#### 4.2.1. Select Computer Groups

Select `Add Non-domain Computers`
- This field supports wildcard, so it is possible to use `prefix*`, `*suffix`, `*middle-fix*` or just leave as `*` and filter sources based on certificate signers

Select `Add Cerificates`
- Add the relevant issuers that signed the forwarder client certificates
- The issuers will need to be in the `Root` or `CA` stores

![image](https://github.com/user-attachments/assets/43d5499c-9c79-4a98-8485-eaa8b8a2147f)

#### 4.2.2. Select Events

This is the same filter as the `Filter Current Log` function in the event viewer

![image](https://github.com/user-attachments/assets/df5b04d0-009e-4ea0-a266-79684bb95aec)

![image](https://github.com/user-attachments/assets/363f2a7c-6460-4baf-9783-d7545dd14809)

#### 4.2.3. Advanced

Select `HTTPS` under `Protocol`

![image](https://github.com/user-attachments/assets/e4af7e64-e8da-4455-9f1e-506643a8c4a5)

## 5. Configure events forwarding on the forwarder

### 5.1. Grant permission on the client certificate private keys

Open local machine certificate manager (`certlm.msc`), select `Manage Private Keys` on the client certificate:

![image](https://github.com/user-attachments/assets/7c2eb1cc-1ce1-4f15-bccd-db559e3b314d)

Assign `Read` permissions to `NETWORK SERVICE`:

![image](https://github.com/user-attachments/assets/676212c3-8fcf-4b5d-82da-b048bf648175)

### 5.2. Configure events forwarding 

Group Policy Editer → Computer Configuration → Policies → Windows Settings → Administrative Templates → Windows Components → Event Forwarding → Configure target Subscription Manager

Select `Enabled`

![image](https://github.com/user-attachments/assets/df063baf-d89b-40d3-9f5c-8c3b172786ba)

Select `Show` under `SubscriptionManagers` and enter:

```
Server=https://<collector-name>:5986/wsman/SubscriptionManager/WEC,Refresh=10,IssuerCA=<issuer-certificate-thumbprint>
```

![image](https://github.com/user-attachments/assets/93137a93-3b66-46e4-84f4-bb1a6a3658cf)

## 6. Successful connection

### 6.1. Expected success events sequence on the forwarder

Log location: Applications and Services → Microsoft → Windows → Eventlog-ForwardingPlugin → Operational

- 106: `Subscription policy has changed.  Forwarder is adjusting its subscriptions according to the subscription manager(s) in the updated policy.`

  ![image](https://github.com/user-attachments/assets/f003979e-6773-45f2-b11b-afb48d42835f)

- 100: `The subscription <subscription-name> is created successfully.`

  ![image](https://github.com/user-attachments/assets/bd1b9bc1-969a-4d14-bcff-65996000b7e1)

- 104: `The forwarder has successfully connected to the subscription manager at address https://<collector-name>:5986/wsman/SubscriptionManager/WEC.`

  ![image](https://github.com/user-attachments/assets/b21d69c5-2082-45aa-bfd9-8217bdd8c95d)

### 6.2. Subscription status on the collector

![image](https://github.com/user-attachments/assets/ee991372-7269-4001-91cb-6be9ac8e604e)

![image](https://github.com/user-attachments/assets/84db5a6d-5df0-4a74-86e1-5a6f05ee1290)

The first event received would likely be a `The file name is too long.` event - this is normal, the events would take a few minutes to start coming in


## 7. Troubleshooing

Log location: Applications and Services → Microsoft → Windows → Eventlog-ForwardingPlugin → Operational

### 107:

`The WS-Management service cannot find the certificate that was requested.`

![image](https://github.com/user-attachments/assets/e905edfb-caf9-4efa-b7b7-6d8ae64f4154)

Possible cause: There are no certificates in `Cert:\LocalMachine\My` store that are signed by the certificate thumbprint specified by `IssuerCA`.

Resolution: Check that the client certificate is properly configured.

`Keyset does not exist`

![image](https://github.com/user-attachments/assets/1d973662-bf1c-4902-aaf8-39f12e916513)

Possible cause: A certificate signed by the certificate thumbprint specified by `IssuerCA` exists, but `NETWORK SERVICE` does not have `Read` permission on the private key

Resolution: Assign `Read` permission on the private key to `NETWORK SERVICE` under `certlm.msc`

### 105:

`The SSL certificate is signed by an unknown certificate authority.`

![image](https://github.com/user-attachments/assets/c8b4c7a9-879d-42dc-a629-32a53ac5e724)

Possible cause: The certificate used by the collector WinRM HTTPS listener is not trusted by the forwarder

Resolution: Import the issuer CA into the forwarder trust stores

`The SSL certificate contains a common name (CN) that does not match the hostname.`

![image](https://github.com/user-attachments/assets/80b5cc45-4751-4e4e-bb02-29385e008662)

Possible cause: The FQDN or IP is not present in the subject or subject alternative names (SANs) of the certificate used by the collector WinRM HTTPS listener

Resolution: Generate a collector certificate that contains the FQDN or IP in the subject, or include the FQDN and/or IP in the SANs

`The WinRM client cannot process the request. The destination computer (<collector>:5986) returned an &apos;access denied&apos; error.`

![image](https://github.com/user-attachments/assets/47b16a4c-4aa2-4119-be58-1e135ffec879)

Possible cause: The issue CA that signed the forwarder certificate is not added in the subscriber configuration of the collector

Resolution: Check that the CA is properly configured under `Select Computer Groups` in the subscriber configuration of the collector

`The client cannot connect to the destination specified in the request.`

![image](https://github.com/user-attachments/assets/e5aee4da-c37b-4898-9947-21371a96edbb)

Possible cause: The collector is down or the collector WinRM HTTPS listener is not configured

Resolution: This can usually occur when the collector is rebooting, or the collector WinRM HTTPS listener is deleted accidentally

`The WinRM client sent a request to an HTTP server and got a response saying the requested HTTP URL was not available.`

![image](https://github.com/user-attachments/assets/005a0916-cc35-403b-978b-c84f4fffc3ee)


Possible cause:
- This error message is somewhat misleading, this doesn't mean that the collector cannot be reached (which would be the error above)
- This actually means that `NETWORK SERVICE` does not have permissions to one of the selected event channels to collect on the collector

Resolution: Add `NETWORK SERVICE` to the `Event Log Readers` group on the collector

### 101:

`The subscription default is created, but one or more channels in the query could not be read at this time.`

![image](https://github.com/user-attachments/assets/619b9477-2dc8-4605-b9ca-ed7328d67bd2)

Possible cause: `NETWORK SERVICE` does not have access to one or more event log sources (usually the `Security` logs) on the forwarder

Resolution: Add `NETWORK SERVICE` to the `Event Log Readers` group on the forwarder
