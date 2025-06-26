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
