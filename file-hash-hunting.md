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

Edit `HashAlgorithms` field to specify the desired hashing algorithms

Example:

```xml
<Sysmon schemaversion="4.90">
	<HashAlgorithms>md5,sha256</HashAlgorithms>
⋮
```

Sysmon supports MD5, SHA1, SHA256 and IMPHASH

Wildcard `*` means it would include all supported hashing algorithms (i.e. `<HashAlgorithms>*</HashAlgorithms>` == `<HashAlgorithms>md5,sha1,sha256,IMPHASH</HashAlgorithms>`)

> [!Tip]
>
> The sysmon events for Windows that have file hashes are:
> - ProcessCreate
> - DriverLoad
> - ImageLoad
> - FileCreateStreamHash
> - FileDelete
> - ClipboardChange
> - FileDeleteDetected
> - FileBlockExecutable
> - FileBlockShredding
> - FileExecutableDetected
>
> This can be confirmed by running `sysmon /s` and check the schemas for events that has `Hashes` field

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

Edit `HashAlgorithms` field to specify the desired hashing algorithms

Example:

```xml
<Sysmon schemaversion="4.82">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
⋮
```

Sysmon supports MD5, SHA1, SHA256 and IMPHASH

Wildcard `*` means it would include all supported hashing algorithms (i.e. `<HashAlgorithms>*</HashAlgorithms>` == `<HashAlgorithms>md5,sha1,sha256,IMPHASH</HashAlgorithms>`)

> [!Tip]
>
> The sysmon events for Linux that have file hashes are:
> - ProcessCreate
> - DriverLoad
> - ImageLoad
> - FileCreateStreamHash
> - FileDelete
> - ClipboardChange
> - FileDeleteDetected
>
> This can be confirmed by running `sysmon -s` and check the schemas for events that has `Hashes` field

```sh
sysmon -i main.xml
```
