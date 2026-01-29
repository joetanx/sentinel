<details><summary><h2>0. Setup Sentinel Data Lake</h2></summary>

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

## 1. Using Sentinel MCP with VS Code

### 1.1. Using VS Code with GitHub Enterprise account

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

### 1.2. Adding data exploration MCP server to VS Code

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

Verify account signed in (note that the GHE.com account can be different from the MCP Server account):

![](https://github.com/user-attachments/assets/2ed60927-3f68-4e25-88e7-8bab63743332)

### 1.3. VS Code MCP server configuration file

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

### 1.4. Using data exploration MCP server

The agent asks for permission to use the tool:

![](https://github.com/user-attachments/assets/80c0d64e-06fd-48dd-a158-eccab9e7cde3)

![](https://github.com/user-attachments/assets/a7a5b54c-5b9c-4538-945b-afb41055800c)

If the agent provides an input to the tool, the input can be reviewed with the permission request:

![](https://github.com/user-attachments/assets/3f1caa4f-3373-49b8-ba49-9346f56c1382)

![](https://github.com/user-attachments/assets/f3cf687d-8534-4917-b12f-c5d2d954f868)

### 1.5. VS Code agent instructions

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

The agent followed instructions and identified the workspace and table to query:

![](https://github.com/user-attachments/assets/2e8a12fd-0dfe-48bf-beb6-5c70e15c9f08)

![](https://github.com/user-attachments/assets/cb55a138-eb0c-4dfd-ac5e-e7dc93182387)

The agent can request for multiple tool usages wherever applicable:

![](https://github.com/user-attachments/assets/56b80743-793c-4db8-8fde-046375a89773)

![](https://github.com/user-attachments/assets/dd3441fd-1aee-479f-9650-486639bd01eb)

The agent interaction corresponds to this incident:

![](https://github.com/user-attachments/assets/f8cb6e52-b5bf-442e-8901-1afcca5dc491)

## 2. Using Sentinel MCP with Foundry

## 3. Using Sentinel MCP with third-party agent framework

Example: n8n

### 3.1. Create app registration for Sentinel MCP Server

![](https://github.com/user-attachments/assets/33df02d0-0288-49a2-9bf8-e36c4b836d25)

### 3.2. Configure API permission

![](https://github.com/user-attachments/assets/8bba6a14-91a9-4bd6-b40f-2fe91987d1d5)

![](https://github.com/user-attachments/assets/cfb27249-0cda-4475-a428-00c857fba6d3)

Search for and select `Sentinel Platform Services`:

![](https://github.com/user-attachments/assets/7ddad326-9974-4425-813f-b89d20b20094)

![](https://github.com/user-attachments/assets/89066806-8f22-4036-9fd3-9bb584c48ce8)

![](https://github.com/user-attachments/assets/b5830a18-98bc-4d20-8d59-4b5457de6c99)

### 3.3. Create client secret

![](https://github.com/user-attachments/assets/ad2649ab-6dd1-4c77-8a66-efaacf990b68)

### 3.4. Configure redirect URL

Example: https://n8n.vx/rest/oauth2-credential/callback

![](https://github.com/user-attachments/assets/4ac07b8a-6b8b-455c-b500-72601afb8392)

App registration → Authentication → Add a platform:

![](https://github.com/user-attachments/assets/55fa0ffd-ace6-485e-8f38-3cdbfd599175)

![](https://github.com/user-attachments/assets/1b9db5a5-2c62-4a50-be87-ea918272746c)

![](https://github.com/user-attachments/assets/ebe0f25d-ae54-45a9-b72d-d03f8eec9905)
