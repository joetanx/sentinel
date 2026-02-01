## 0. Preparations

### 0.1. Permissions and platforms

|Tool|Permissions|Agent platforms|
|---|---|---|
|[Data exploration](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-data-exploration-tool)|Security Reader at Entra level|• Microsoft Foundry<br>• Visual Studio Code<br>• Third-party agent framework (not officially documented)|
|[Triage](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)|Tools available corresponds to<br>[Defender Unified RBAC permissions](https://learn.microsoft.com/en-us/defender-xdr/custom-permissions-details)|• Visual Studio Code|

<details><summary><h3>0.2. Setup Sentinel Data Lake (SDL)</h3></summary>

![](https://github.com/user-attachments/assets/781430ac-9a0f-49e3-a992-2fbde10b92f8)

|Setup|Benefits and impact|
|---|---|
|![](https://github.com/user-attachments/assets/83519e34-ed76-4ae5-85f0-4bfc5761dabc)|![](https://github.com/user-attachments/assets/d6ee69e2-99b2-45cb-b50c-9039b1a09a4d)|

Data lake setup takes some time:

![](https://github.com/user-attachments/assets/e973cd71-45b0-43c9-869f-5098e702a0c7)

![](https://github.com/user-attachments/assets/26d11181-1fcb-4593-a525-984641bc3a0a)

Data lake setup completed:

![](https://github.com/user-attachments/assets/d0d301c0-d86c-4629-8b2d-aacdac5786d2)

</details>

### 0.3. [Setup Foundry resource](https://github.com/joetanx/mslab/blob/main/foundry.md)

<details><summary><h3>0.4. Using VS Code with GitHub Enterprise account</h3></summary>

Click on the GitHub Copilot icon and select `Use AI Features`:

![](https://github.com/user-attachments/assets/bfe18248-f855-4672-a76c-eb819dd720f9)

Select `Continue with GHE.com`:

![](https://github.com/user-attachments/assets/f6d81a20-be50-4aea-a4be-95521980249b)

Enter the GHE.com instance in top bar:

![](https://github.com/user-attachments/assets/cfc20147-fe69-4ba5-90ed-c96bff63dc04)

Sign in to GHE instance:

![](https://github.com/user-attachments/assets/1217b357-e246-4615-98d1-4378ce81c470)

![](https://github.com/user-attachments/assets/71388bcc-7c5b-4b44-b3ad-4acb2e0b93a5)

![](https://github.com/user-attachments/assets/633b1547-2e32-494b-9f2b-36c63907ef90)

![](https://github.com/user-attachments/assets/19205083-73da-4a43-b50a-25bc8f7ae3d6)

Verify account signed in:

![](https://github.com/user-attachments/assets/dd844dd7-f179-4919-8b1b-9293ce1e79f1)

</details>

### 0.5. VS Code MCP server configuration file

Config file location: `%USERPROFILE%\AppData\Roaming\Code\User\mcp.json`

Example:

```json
{
  "servers": {
    "Data exploration": {
      "url": "https://sentinel.microsoft.com/mcp/data-exploration",
      "type": "http"
    },
    "Triage": {
      "url": "https://sentinel.microsoft.com/mcp/triage",
      "type": "http"
    },
    "SCP agent creation": {
      "url": "https://sentinel.microsoft.com/mcp/security-copilot-agent-creation",
      "type": "http"
    }
  },
  "inputs": []
}
```

The controls to start, stop or restart MCP servers:

![](https://github.com/user-attachments/assets/2330e139-0393-4c8e-9357-fb3111f16364)

Clicking `More...` brings up the option to `Disconnect Account` (so that the MCP server can be signed in with a different account with different access):

![](https://github.com/user-attachments/assets/ad17596a-bcf7-461d-874c-082df5c5514c)

> [!Tip]
>
> Opening the `mcp.json` from _Explorer_ or _Open Recent_ doesn't bring up the MCP controls
>
> Select `Configure Tools...` from the chat pane:
>
> ![](https://github.com/user-attachments/assets/052b69af-6ad9-4f19-a9a7-616e720e1f1c)
>
> And click on the configure (gear) icon to bring up `mcp.json` files with the MCP controls
>
> ![](https://github.com/user-attachments/assets/19132ebf-1d14-45c5-9a4c-367cea024504)

## 1. Using data exploration tools [with VS Code](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-use-tool-visual-studio-code)

### 1.1. Adding data exploration tools to VS Code

Click on top bar and select `Show and Run Commands >` (or press `Ctrl` + `Shift` + `P`):

![](https://github.com/user-attachments/assets/cb8e2f24-c927-4ed5-8bc5-a69c014e2ed5)

Search for `MCP` and select `MCP: Add Server...`:

![](https://github.com/user-attachments/assets/a0e51f1c-d604-45ea-a4dd-4357e4669140)

Select `HTTP (HTTP or Server-Sent Events)`:

![](https://github.com/user-attachments/assets/e81900e1-3447-4cc5-a5ff-8e1792bc79db)

Enter the data exploration MCP server URL https://sentinel.microsoft.com/mcp/data-exploration:

![](https://github.com/user-attachments/assets/9c3822a3-0a0f-4724-9b48-a40861e8411e)

Enter an ID for the MCP server:

![](https://github.com/user-attachments/assets/d148e191-484d-4cbb-a527-d95ec101272b)

Authenticate to connect the MCP server:

![](https://github.com/user-attachments/assets/2f50df89-397d-45f0-8698-e01e9e45339a)

![](https://github.com/user-attachments/assets/f4646f32-0b19-41a8-963b-a240cfe8b36b)

Verify account signed in (notice that the GHE.com account can be different from the MCP Server account):

![](https://github.com/user-attachments/assets/2ed60927-3f68-4e25-88e7-8bab63743332)

### 1.2. Using data exploration tools

The agent asks for permission to use the tool:

![](https://github.com/user-attachments/assets/5c276f2a-7284-4f90-ac96-f3798a22eaaa)

![](https://github.com/user-attachments/assets/9d2f0eac-8820-4ed9-b0b5-d112cf902cb2)

If the agent provides an input to the tool, the input can be reviewed with the permission request:

![](https://github.com/user-attachments/assets/a1ce5881-6f0c-4c2e-ab6a-204c9aefde50)

![](https://github.com/user-attachments/assets/56160371-b976-4321-9d85-bdde5a05c8ab)

### 1.3. VS Code agent instructions

VS Code supports multiple types of Markdown-based [instructions files](https://code.visualstudio.com/docs/copilot/customization/custom-instructions#_type-of-instructions-files)

e.g.: `%USERPROFILE%\AppData\Roaming\Code\User\prompts\security-operations.instructions.md`

The agent can be made more purpose driven with instructions like below:

```md
---
applyTo: '**'
---
You are a security operations assistant. 
- default workspace: delta-soc f119dae4-df67-44a1-b5c7-caa589bcc8ce 
- incidents: `SecurityIncident` table 
- alerts: `SecurityAlert` table 
- incident IDs are in the `ProviderIncidentId` column 
- the array in `AlertIds` column from `SecurityIncident` table provides alert IDs that corresponds to `SystemAlertId` column in `SecurityAlert` table 
```

The agent used the instructions to identify the workspace and table to query:

![](https://github.com/user-attachments/assets/2d42a296-2ca0-488f-9082-2c98c15d6bb0)

![](https://github.com/user-attachments/assets/a57013b6-18db-439f-adcf-69d970fd5a03)

The agent can request for multiple tool usages wherever applicable:

![](https://github.com/user-attachments/assets/cf32e15d-96e3-485f-bc03-6cf7bf05781b)

![](https://github.com/user-attachments/assets/385c211e-6d20-4f87-b76b-02f553acad4d)

The agent interaction corresponds to this incident:

![](https://github.com/user-attachments/assets/f8cb6e52-b5bf-442e-8901-1afcca5dc491)

## 2. Using data exploration tools [with Foundry](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-use-tool-azure-ai-foundry)

### 2.1. Create Foundry agent

![](https://github.com/user-attachments/assets/abdd595e-9bd8-470b-97f8-731f5a014edc)

### 2.2. Adding data exploration tools to Foundry agent

#### 2.2.1. Option 1: create from the agent

![](https://github.com/user-attachments/assets/b9c8a2ed-b571-4ce4-8aa3-8eef241e0a81)

![](https://github.com/user-attachments/assets/e4afe540-a73a-4ef9-949f-4f0283e9b32a)

![](https://github.com/user-attachments/assets/4ca2f30f-ce86-4fbe-b259-df55910186b1)

#### 2.2.2. Option 2: create from tools page, then connect to the agent

![](https://github.com/user-attachments/assets/b94d8ce4-769c-4851-becd-7bd27881ceed)

![](https://github.com/user-attachments/assets/c535f86d-7316-44fc-a5ae-7483992ae518)

![](https://github.com/user-attachments/assets/f021f2e2-db3b-43b5-94c2-b61e79cc787c)

### 2.3. Using data exploration tools

The agent asks for permission to use the tool:

![](https://github.com/user-attachments/assets/e388aec8-7ab7-472a-88dd-8b1d325cc053)

![](https://github.com/user-attachments/assets/d6f14b53-c39d-4f2a-b5d9-06ac24e124c0)

If the agent provides an input to the tool, the input can be reviewed with the permission request:

- agents can make mistakes, notice that it first attempts to send the query in natural language:

  ![](https://github.com/user-attachments/assets/2ec1bb98-2715-4e6a-8d4a-b491c5a31a40)

- it then realized that it should send a KQL:

  ![](https://github.com/user-attachments/assets/aab63f67-8cf4-4282-a27d-2fd288920d2d)

![](https://github.com/user-attachments/assets/cf19f7a1-1ec8-40cd-bd2b-54243067304d)

### 2.4. Foundry agent instructions

The agent can be made more purpose driven with instructions like below:

```md
You are a security operations assistant. 
- default workspace: delta-soc f119dae4-df67-44a1-b5c7-caa589bcc8ce 
- incidents: `SecurityIncident` table 
- alerts: `SecurityAlert` table 
- incident IDs are in the `ProviderIncidentId` column 
- the array in `AlertIds` column from `SecurityIncident` table provides alert IDs that corresponds to `SystemAlertId` column in `SecurityAlert` table 
```

![](https://github.com/user-attachments/assets/b77dccc2-075e-4852-ae52-290a09363c7a)

The agent used the instructions to identify the workspace and table to query:

![](https://github.com/user-attachments/assets/9f636e0e-6f05-4789-aa5c-6935775aa134)

![](https://github.com/user-attachments/assets/e60cb493-c5f9-4f72-a195-70573c0fb48f)

The agent can request for multiple tool usages wherever applicable:

![](https://github.com/user-attachments/assets/26cf7e0e-c796-4c88-9be2-91e5af767c8d)

## 3. Using data exploration tools with third-party agent framework

While not officially documented, the [custom tool instructions](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-use-tool-azure-ai-foundry#add-a-custom-tool-collection) to create app registration works with third party agent frameworks like n8n

### 3.1. Create app registration for Sentinel MCP Server

![](https://github.com/user-attachments/assets/33df02d0-0288-49a2-9bf8-e36c4b836d25)

#### 3.1.1. Configure API permission

![](https://github.com/user-attachments/assets/8bba6a14-91a9-4bd6-b40f-2fe91987d1d5)

![](https://github.com/user-attachments/assets/cfb27249-0cda-4475-a428-00c857fba6d3)

Search for and select `Sentinel Platform Services`:

![](https://github.com/user-attachments/assets/7ddad326-9974-4425-813f-b89d20b20094)

![](https://github.com/user-attachments/assets/89066806-8f22-4036-9fd3-9bb584c48ce8)

![](https://github.com/user-attachments/assets/b5830a18-98bc-4d20-8d59-4b5457de6c99)

#### 3.1.2. Create client secret

![](https://github.com/user-attachments/assets/ad2649ab-6dd1-4c77-8a66-efaacf990b68)

#### 3.1.3. Configure redirect URL

Example: https://n8n.vx/rest/oauth2-credential/callback

![](https://github.com/user-attachments/assets/4ac07b8a-6b8b-455c-b500-72601afb8392)

App registration → Authentication → Add a platform:

![](https://github.com/user-attachments/assets/55fa0ffd-ace6-485e-8f38-3cdbfd599175)

![](https://github.com/user-attachments/assets/1b9db5a5-2c62-4a50-be87-ea918272746c)

![](https://github.com/user-attachments/assets/ebe0f25d-ae54-45a9-b72d-d03f8eec9905)

### 3.2. Adding data exploration tools to n8n agent

![](https://github.com/user-attachments/assets/4008640a-cb05-4721-8387-34872140082c)

![](https://github.com/user-attachments/assets/2c7c82c4-00bf-46b2-a278-ff787b5ed478)

Configure OAuth2 authentication in n8n:

> [!Important]
>
> The OAuth Redirect URL match match the redirect URI configured in the app registration
>
> The n8n environment variable `N8N_EDITOR_BASE_URL` forms the base of the redirect URL (e.g. https://n8n.vx/)

|Parameter|Value|
|---|---|
|Use Dynamic Client Registration|No|
|Grant Type|Authorization Code|
|Authorization URL|https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize|
|Access Token URL|https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token|
|Client ID|The client ID of the app registration created|
|Client Secret|The client secret created for the app registration|
|Scope|`4500ebfb-89b6-4b14-a480-7f749797bfcd/.default`|

![](https://github.com/user-attachments/assets/9cffd8f1-3bc1-4b47-9266-1e854a997862)

Click `Connect my account` and complete the Entra ID sign in:

![](https://github.com/user-attachments/assets/000d6189-5007-4f66-8d36-642724a7490e)

The account show `Account connected` upon successfully sign-in:

![](https://github.com/user-attachments/assets/323a2b3d-5feb-4280-829d-af786ba7f03e)

Select the "play" button (Execute step) to test the MCP connection:

![](https://github.com/user-attachments/assets/1ee3e653-f610-4dd4-ad3a-2c0cb72b4692)

The MCP connection is function if the tools are listed:

![](https://github.com/user-attachments/assets/707c4b2e-1589-4711-a7da-65c5616e3441)

### 3.3. Using data exploration tools

![](https://github.com/user-attachments/assets/46693a74-f900-4a93-abb7-ade6004d6a51)

![](https://github.com/user-attachments/assets/ff729b2f-1211-45c2-9da6-867b7836ee76)

### 3.4. n8n agent instructions

The agent can be made more purpose driven with instructions like below:

```md
You are a security operations assistant. 
- default workspace: delta-soc f119dae4-df67-44a1-b5c7-caa589bcc8ce 
- incidents: `SecurityIncident` table 
- alerts: `SecurityAlert` table 
- incident IDs are in the `ProviderIncidentId` column 
- the array in `AlertIds` column from `SecurityIncident` table provides alert IDs that corresponds to `SystemAlertId` column in `SecurityAlert` table 
```

![](https://github.com/user-attachments/assets/b428d7bf-bfaf-431a-9dd2-4afbb0fb5385)

![](https://github.com/user-attachments/assets/41b92442-463d-409d-ad51-c712eb4530f6)

![](https://github.com/user-attachments/assets/b15f138b-3e7b-4497-8fd6-39276de1b1e8)

## 4. Using triage tools

### 4.1. Adding triage to VS Code

Click on top bar and select `Show and Run Commands >` (or press `Ctrl` + `Shift` + `P`):

![](https://github.com/user-attachments/assets/cb8e2f24-c927-4ed5-8bc5-a69c014e2ed5)

Search for `MCP` and select `MCP: Add Server...`:

![](https://github.com/user-attachments/assets/a0e51f1c-d604-45ea-a4dd-4357e4669140)

Select `HTTP (HTTP or Server-Sent Events)`:

![](https://github.com/user-attachments/assets/e81900e1-3447-4cc5-a5ff-8e1792bc79db)

Enter the data exploration MCP server URL https://sentinel.microsoft.com/mcp/triage:

![](https://github.com/user-attachments/assets/aa895675-d049-40e3-9ebf-b3663e7128a5)

Enter an ID for the MCP server:

![](https://github.com/user-attachments/assets/9cb1769f-f813-45de-90b9-1c6d0743260b)

Authenticate to connect the MCP server:

![](https://github.com/user-attachments/assets/41298466-d32a-4c41-9116-8e167218406c)

![](https://github.com/user-attachments/assets/3386d2a8-9210-459b-8345-525f70b2e499)

![](https://github.com/user-attachments/assets/6507cefc-331e-419a-9bd6-01d28418e258)

Verify account signed in (notice that the GHE.com account can be different from the MCP Server accounts):

![](https://github.com/user-attachments/assets/3265d5fb-d322-4538-9212-7919052c1e9b)

### 4.2. Using triage tools

> [!Important]
>
> Agents can perform poorly when being exposed to too many tools, mainly due to:
> 1. All enabled tools are processed by agents, which means that the cumulative tool descriptions are fit into agent context window
> 2. Tools provided under a MCP server usually have similar though distinct functions, this makes it different for agents to pick the right tool to use because the desriptions may be semantically similar
>
> The triage tool collections has 27 tools, the selection tools to enable can vastly impact the agent performance

The below example prompts are performed with the follow tools enabled:

![](https://github.com/user-attachments/assets/49c83549-dd66-4005-b735-a90bdb138a6c)

#### Prompt: _list incidents from the past 3 days_

![](https://github.com/user-attachments/assets/f4587c5d-8fb3-4ac4-acbe-0d76c01ad723)

![](https://github.com/user-attachments/assets/84ea4776-4309-46fc-b4cf-0be4340882a3)

#### Prompt: _get alerts for incident 1762_

![](https://github.com/user-attachments/assets/b4a2f778-0f9e-4444-91bb-b912f336f759)

![](https://github.com/user-attachments/assets/9be309f5-748d-4748-ba1c-c13e24715eeb)

#### Prompt: _run KQL queries to search for windows logon failure and syslog password fail events_

![](https://github.com/user-attachments/assets/d7bb608d-8a30-47fd-af63-f401ffec57ce)

![](https://github.com/user-attachments/assets/38df367a-d95a-458b-b4cf-498f4b1ec3fa)

![](https://github.com/user-attachments/assets/5326be72-a5bf-4d17-82e1-340d9e9a411f)

#### Prompt: _review the machine information for `alpha-vm-winsvr` and `alpha-vm-langflow`_

![](https://github.com/user-attachments/assets/a470c6cc-90ee-4272-bd9a-c262cfe0e3cc)

![](https://github.com/user-attachments/assets/044a524c-c561-429b-9488-0e2c40bcb5c9)

![](https://github.com/user-attachments/assets/9cd9c2d8-afb7-4bfa-a970-496661a359db)

#### Prompt: _what are the malware or exploit alerts seen on these 2 machines?_

![](https://github.com/user-attachments/assets/e1735007-d54e-4ee7-a638-4af4062752b8)

![](https://github.com/user-attachments/assets/8bea9bf3-33cd-4ace-a8b6-e539ed0a884f)

![](https://github.com/user-attachments/assets/7c0a163a-3212-4817-a254-073c5073234c)

![](https://github.com/user-attachments/assets/dc3ec276-7278-4b8b-b9fe-c00a31222486)
