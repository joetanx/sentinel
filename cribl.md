![image](https://github.com/user-attachments/assets/27e22ab3-3fe9-4730-96f0-a604fdc4740a)Ref:
- https://docs.cribl.io/stream/usecase-azure-workspace/
- https://docs.cribl.io/stream/destinations-sentinel/

## 1. Setup Entra Identity for Cribl

### 1.1. Create app registration

> [!Note]
>
> Take note of the `Application (client) ID` and `Directory (tenant) ID`; these will be required later.

![image](https://github.com/user-attachments/assets/e3035712-cabe-4480-9d86-0b5fe0f2f80f)

### 1.2. Create client secret

> [!Important]
>
> The client secret is displayed **only once**, copy and store it securely right after creation
>
> There is no way to retrieve the client secret if it's lost, it will need to be deleted and create a new one

![image](https://github.com/user-attachments/assets/002f5684-6d55-4a38-ad8a-f19f0dfd3353)

## 2. Setup data collection

### 2.1. Create DCE (Data Collection Endpoint)

![image](https://github.com/user-attachments/assets/a33250ec-7ae3-499f-9b45-acd7f71ff8b6)

### 2.2. Create DCR (Data Collection Rule) using [Cribl DCR template](https://docs.cribl.io/stream/usecase-webhook-azure-sentinel-dcr-template/)

Go to the created DCE and copy the Resource ID in JSON view:

![image](https://github.com/user-attachments/assets/a869cd40-4c6f-4879-9db0-878420f7cd8c)

Get the Resource ID for the target LAW (Log Analytics Workspace):

![image](https://github.com/user-attachments/assets/0391c7ae-9c03-40b2-87aa-014b044f911a)

Deploy DCR from [Cribl DCR template](https://docs.cribl.io/stream/usecase-webhook-azure-sentinel-dcr-template/)
- Go to `Deploy a custom template`
- Select `Build your own template in the editor`
- Copy and paste the [Cribl DCR template](https://docs.cribl.io/stream/usecase-webhook-azure-sentinel-dcr-template/)

![image](https://github.com/user-attachments/assets/1e7483ea-2fc2-416e-a8cd-b57af7155cc3)

Paste the DCE and LAW Resource IDs

![image](https://github.com/user-attachments/assets/e082cdb2-6f01-40c7-b17d-42f24eb6f1d5)

Add role assignment to the DCR

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

![image](https://github.com/user-attachments/assets/979e1338-a1fd-4615-ac8a-ffa1312ad45c)

Select the Cribl application:

> [!Tip]
>
> https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#assign-a-role-to-the-application
>
> By default, Microsoft Entra applications aren't displayed in the available options. Search for the application by name to find it.

![image](https://github.com/user-attachments/assets/6da5cef8-aa75-4b80-90eb-ca194138f42a)

## 3. Configure data destination to Sentinel in Cribl

![image](https://github.com/user-attachments/assets/9e4c39d4-9a71-44db-88f9-c0e857dd1413)

### 3.1. General Settings

Retrieving required information for configuration:

|Field|Description|
|---|---|
|Data collection endpoint|Data collection endpoint (DCE) in the format `https://<endpoint-name>.<identifier>.<region>.ingest.monitor.azure.com`.<br>![image](https://github.com/user-attachments/assets/986092e4-0bf8-4978-b6f7-3c316c4812d5)|
|Data collection rule ID|DCR Immutable ID:<br>![image](https://github.com/user-attachments/assets/6fa24e31-2a77-44e8-8be9-7ae40b172446)|
|Stream name|Name of the Sentinel table in which to store events.<br>![image](https://github.com/user-attachments/assets/95a6d339-6144-46fb-b602-c0f916348407)|

Cribl provides the [Azure Resource Graph Explorer](https://docs.cribl.io/stream/usecase-azure-sentinel/#obtaining-url) to retrieve the required information

```kusto
Resources
| where type =~ 'microsoft.insights/datacollectionrules'
| mv-expand Streams= properties['dataFlows']
| project name, id, DCE = tostring(properties['dataCollectionEndpointId']), ImmutableId = properties['immutableId'], StreamName = Streams['streams'][0]
| join kind=leftouter (Resources
| where type =~ 'microsoft.insights/datacollectionendpoints'
| project name,  DCE = tostring(id), endpoint = properties['logsIngestion']['endpoint']) on DCE
| project name, StreamName, Endpoint = strcat(endpoint, '/dataCollectionRules/',ImmutableId,'/streams/',StreamName,'?api-version=2023-01-01')
```

![image](https://github.com/user-attachments/assets/a38e9f2b-eac9-461a-b003-c95cc7ccfde7)

Configuration of Sentinel as data destination in Cribl can be done using `URL` or `ID`

![image](https://github.com/user-attachments/assets/48ac4969-7c37-43fb-95ab-3e5ec607ffdf)

![image](https://github.com/user-attachments/assets/6621652e-86b6-44fb-8b22-07adc916dbc8)

![image](https://github.com/user-attachments/assets/41a9b465-e836-493d-99b7-f021e5dfe4a4)

![image](https://github.com/user-attachments/assets/0e3cb3d7-d4f6-4756-9877-f55573bada57)

### 3.2. Authentication

|Field|Description|
|---|---|
|Login URL|The token API endpoint for the Microsoft identity platform. Use the string: `https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token`, substituting `<tenant_id>` with Entra ID tenant ID.<br>The Directory (tenant) ID listed on the app's Overview page.<br>![image](https://github.com/user-attachments/assets/80678144-9c0a-41d5-8ee7-91551525cbf5)|
|OAuth secret|The client secret generated in [1.2. Create client secret](#12-create-client-secret)|
|Client ID|The Application (client) ID listed on the app's Overview page.<br>![image](https://github.com/user-attachments/assets/03764fb0-7926-4966-93ba-b1d40b3922fe)|

> [!Tip]
>
> The client ID is entered as a json constant (i.e. enclosing the value with backticks <code>`</code>)

![image](https://github.com/user-attachments/assets/53bb2076-08de-4484-84a0-bb4437528cbe)

### 3.3. Test the data destination

![image](https://github.com/user-attachments/assets/fd9d6568-67ac-4dff-b6de-3af4b3dac25c)

![image](https://github.com/user-attachments/assets/e8730675-f156-4941-aa5c-0e819bf6ea85)

## 4. Get Cribl packs for Sentinel

Processing → Packs → Add Pack → Add from Dispensary

![image](https://github.com/user-attachments/assets/54f4ce5b-b383-4372-ae60-a74a7f87b24a)

Search for `Sentinel`

![image](https://github.com/user-attachments/assets/7ddca5dd-5284-443a-a618-34ecdd45ef74)

The `Microsoft Sentinel` pack by Christoph Dittmann (cdittmann@cribl.io) includes a wef pipeline to parse Windows events to columns in the SecurityEvent table

![image](https://github.com/user-attachments/assets/6d4217a4-e186-41d3-8ac4-da8e27747e7f)

The `Microsoft Sentinel Syslog` pack by Dan Schmitz (dschmitz@cribl.io) includes a syslog pipeline to parse syslog events to columns in the Syslog table

![image](https://github.com/user-attachments/assets/89e9de3c-9ab2-4b45-a967-2d0f5b6c88d3)

## 5. Configure pipelines

### 5.1. Syslog pipeline

Go to the `Microsoft Sentinel Syslog` pack and copy the `sentinel_syslog` pipeline

![image](https://github.com/user-attachments/assets/8ebcc2e6-f576-49fa-a946-aa8149f68433)

Paste the pipeline

![image](https://github.com/user-attachments/assets/c25261e7-d978-4e2d-af1c-3caf27819919)

![image](https://github.com/user-attachments/assets/8db4a330-f7f4-4741-9192-1ae5d65ef6c6)

Edit the `Eval` step of the pipeline:
- Change `String(facility) || facilityName` to `facilityName` for the `Facility` field
  - Sentinel accepts `facilityName` (name) but not `facility` (number) for the `Facility` column
- Add field for `SourceSystem`: `'Cribl'`
- Add `SourceSystem` under `Keep fields`

![image](https://github.com/user-attachments/assets/f73ab931-81b6-4a8d-acbe-40c7f88746fa)

### 5.2. WEF pipeline

Go to the `Microsoft Sentinel` pack and copy the `wef_security_events` pipeline

![image](https://github.com/user-attachments/assets/a159426d-9a3a-4a81-addd-182fdcc30c45)

Paste the pipeline

![image](https://github.com/user-attachments/assets/c25261e7-d978-4e2d-af1c-3caf27819919)

![image](https://github.com/user-attachments/assets/fcc68842-57c8-4e84-8051-13261255793f)

#### 5.2.1. Including `EventData` field

A XML or JSON copy of the `EventData` can be contained in the `EventData` field by enabling step 2 or step 6 of the pipeline

![image](https://github.com/user-attachments/assets/e58ace4e-d85c-4035-a17e-b2ae7ad3061d)

The affects how Sentinel receives the event

XML - LAW displays the `EventData` XML as a single line string:

![image](https://github.com/user-attachments/assets/3c567c7e-fbbd-42d7-b64c-0a9dc9dafbdf)

JSON - LAW displays the `EventData` JSON as a JSON object:

![image](https://github.com/user-attachments/assets/24061221-278b-445a-b4ba-c1270c2ba1a8)

A Windows security event ingested directly via AMA conditional enriches the `EventData` field depending on the type of event

Logon failure event (`4625`) does not have `EventData` field populated:

![image](https://github.com/user-attachments/assets/7be6f589-d838-4ee0-99ab-8c9189bd0ad3)

While privileged service event (`4673`) has the `EventData` field as XML, and LAW displays it as a multi-line XML:

![image](https://github.com/user-attachments/assets/a78b9881-f551-4068-8162-7f17d12436fa)

#### 5.2.2. Enriching wef events

A Windows security event ingested directly via AMA enriches the event with `EventLevelName`, `Activity` and `LogonTypeName` fields, this can be done in Cribl via the `Lookup` function

The lookup tables for:
- Event level names is available [here](/windows_security_events.csv)
- Event messages according to the [common security events collected by sentinel](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference) is available [here](/windows_security_events.csv)
- [Logon types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events) is available [here](/windows_logon_type.csv)

Upload the csv to Knowledge → Lookups:

![image](https://github.com/user-attachments/assets/148b8482-0c91-41f6-b9a6-8dc15c2cd98a)

![image](https://github.com/user-attachments/assets/322132e4-d589-41c5-924d-8fd6b616718b)

![image](https://github.com/user-attachments/assets/b2c08eac-eec0-4779-936b-2b3d9863b0f9)

![image](https://github.com/user-attachments/assets/0ebbdd93-e6b5-4e02-abaa-31868ba32e1e)

Add a lookup step to the pipeline for each `Activity` and `LogonTypeName` lookups:

![image](https://github.com/user-attachments/assets/0c006dc6-c0d4-4cf8-94b9-7a10a0564c43)

Place the lookup steps before the clean up step and configure the following:

|Lookup file path|Lookup fields|Output fields|
|---|---|---|
|`windows_event_level.csv`|Lookup Field Name in Event: `Level`<br>Corresponding Field Name in Lookup: `Level`|Output Field Name from Lookup: `EventLevelName`<br>Lookup Field Name in Event: `EventLevelName`|
|`windows_security_events.csv`|Lookup Field Name in Event: `EventID`<br>Corresponding Field Name in Lookup: `EventID`|Output Field Name from Lookup: `Activity`<br>Lookup Field Name in Event: `Activity`|
|`windows_logon_type.csv`|Lookup Field Name in Event: `LogonType`<br>Corresponding Field Name in Lookup: `LogonType`|Output Field Name from Lookup: `LogonTypeName`<br>Lookup Field Name in Event: `LogonTypeName`|

![image](https://github.com/user-attachments/assets/40b7bbf5-950d-41f9-961b-b1fb1b9661d3)

![image](https://github.com/user-attachments/assets/4c4e58c9-85ae-4c9a-9fd2-572810000c6d)

![image](https://github.com/user-attachments/assets/65b0d6f4-ca1c-4dd9-8ddd-e48997dcffaa)

The `Activity` and `LogonTypeName` columns in Sentinel gets populated according to the lookups:

![image](https://github.com/user-attachments/assets/40151074-64da-4d8b-97fe-b76472ccc71a)

#### 5.2.3. Cleaning up some fields

Edit the existing eval function to drop `ThreadID` and `ProcessID`

![image](https://github.com/user-attachments/assets/f2b4b3ae-1ed1-42b6-bc58-baab629ddc3a)

## 6. Configure routes

|Route|Source|Pipeline|Destination|
|---|---|---|---|
|route_wef_to_sentinel|`__inputId=='wef:in_wef'`|sentinel_wef_securityevent|sentinel:out_sentinel_securityevent|
|route_syslog_to_sentinel|`__inputId.startsWith('syslog:in_syslog:')`|sentinel_syslog|sentinel:out_sentinel_syslog|

![image](https://github.com/user-attachments/assets/711d899a-f880-4754-8859-4053f87d8354)

## 7. Verify data flow in Cribl

Sources:

![image](https://github.com/user-attachments/assets/0770ae9d-f96e-4751-95f4-b5b0e371a3eb)

Routes:

![image](https://github.com/user-attachments/assets/e2a201db-f47b-43f0-a087-0c53892f83d5)

Pipelines:

![image](https://github.com/user-attachments/assets/ee1d181d-3758-4cb2-8f39-bd90654177cb)

Destinations:

![image](https://github.com/user-attachments/assets/043e4978-dbbe-475d-8b7d-655c8f1cf526)

## 8. Verify events ingested in Sentinel

SecurityEvent table:

![image](https://github.com/user-attachments/assets/61b59d21-d2e9-40b3-b509-59a3fe02cb57)

Syslog table:

![image](https://github.com/user-attachments/assets/334eee48-9c23-461a-8f3b-e2c4ccd8d39a)
