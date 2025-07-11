## 1. Introduction

The Defender portal (security.microsoft.com) provides unified security operations that integrate solutions for:
- Security information and event management (SIEM)
- Security orchestration, automation, and response (SOAR)
- Extended detection and response (XDR)
- Posture and exposure management
- Cloud security, threat intelligence, and generative AI

Sentinel is generally available in the Defender portal, with or without Defender XDR or an E5 license.

The Defender portal can connect to one primary workspace and multiple secondary workspaces.

> [!Tip]
>
> When Sentinel is onboarded to the Defender portal together Defender XDR, capabilities like incident management and advanced hunting are unified in a single pane of glass.
>
> This reduces tool switching and build a more context-focused investigation that expedites incident response and stops breaches faster.

More details:
- https://learn.microsoft.com/en-us/azure/sentinel/workspaces-defender-portal
- https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-sentinel-onboard

### 1.1. Multi-workspace experience

In a multi-workspace environment, the access to each workspace is controlled by the role assignment (RBAC) to the workspace in Azure; this access control is applied in Defender portal as well.

This write-up uses the following example setup to walk through the experience for connecting workspaces to Defender portal:

|Subscription|Resource Group|Sentinel Workspace|User|
|---|---|---|---|
|AlphaSub|AlphaRG|AlphaLAW|Alpha Administrator|
|BravoSub|BravoRG|BravoLAW|Bravo Administrator|

### 1.2. Defender portal with zero roles assigned

For reference, the Defender portal view for a newly user with no roles assigned is similar to below:

<img width="1592" height="817" alt="image" src="https://github.com/user-attachments/assets/d76bc788-6741-4002-8df9-a026037a0830" />

Since this user does not have any rights to any workspace in the environment, no workspace is visible in the Defender portal:

<img width="1592" height="800" alt="image" src="https://github.com/user-attachments/assets/ed7ee433-c491-4b29-9635-859cfa9e7976" />

> [!Tip]
>
> The free version of MDTI is visible to the user
>
> <img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/3ccaf00f-98cf-42ee-a074-82a33e8d7981" />
>
> <img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/e8890c2b-f4ff-4c1f-a8d0-822abc0b644f" />
>
> <img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/3d8fbd76-7944-4ce0-81b2-0c1d3db3f4c3" />

## 2. Connecting a workspace to Defender portal

### 2.1. Permissions required

The detailed level of access required is documented [here](https://learn.microsoft.com/en-us/azure/sentinel/workspaces-defender-portal#permissions-to-manage-workspaces-and-view-workspace-data) and [here](https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-sentinel-onboard#microsoft-sentinel-prerequisites).

The least privilege access role assignment required is:

|Role|Lowest scope of assignment|
|---|---|
|[Microsoft Sentinel Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#microsoft-sentinel-contributor)|Log Analytics Workspace|
|[User Access Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator)|Subscription|

> [!Tip]
>
> The User Access Administrator role means that this user can assign permissions **on** resources **to** other principals
>
> It is commonly misunderstood that this role allows administration **on** other users, which is not the case
>
> Select `Allow user to assign all roles except privileged administrator roles Owner, UAA, RBAC (Recommended)` as the workspace connection would need to assign several roles within the subscription
>
> <img width="1082" height="716" alt="image" src="https://github.com/user-attachments/assets/6569ffce-152e-479f-863d-165d4d73a1cf" />

### 2.2. Connect a workspace

With the appropriate permissions in place, the user can see the workspace and connect it to Defender portal:

<img width="1592" height="800" alt="image" src="https://github.com/user-attachments/assets/c14717f5-4b53-4fc0-a2c0-3502430d3483" />

> [!Note]
>
> In scenarios where there is a "custodian" group taking care of the Defender portal, a primary workspace must first be connected.
>
> The primary workspace is used to connect Defender XDR, Purview Insider Risk Management (IRM) and Defender for Cloud events.
>
> Other users connecting other workspaces would see this primary workspace, but would not be able to change the primary workspace without [Global Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#global-administrator) or [Security Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#security-administrator) in the Entra ID tenant level

Notice that the _Alpha Administrator_ user can only see _AlphaLAW_ which it has access to, but not _BravoLAW_ which it does not have access to:

<img width="1592" height="800" alt="image" src="https://github.com/user-attachments/assets/5498343b-7cd8-4940-9ccf-974018b43f83" />

The workspace would show as _Connected_ shortly:

> [!Tip]
> 
> Notice that the Sentinel settings such as workspace manager configuration and pricing are available in Defender portal settings

<img width="1592" height="800" alt="image" src="https://github.com/user-attachments/assets/c701af8d-f756-480f-8c03-776824876383" />

> [!Note]
>
> The Sentinel section in the side pane can take some time to show up after workspace connection

## 3. Access Sentinel from Defender portal

### 3.1. Permissions required

The permission required for connecting and access Sentinel are different:

|Action|Role|Scope|
|---|---|---|
|Connecting workspace to Defender portal|Microsoft Sentinel Contributor|Log Analytics Workspace|
|Accessing Sentinel from Defender portal|Microsoft Sentinel * roles based on required access|Resource group that contains the workspace|

Although [this document](https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-sentinel-onboard) says the Microsoft Sentinel roles can be assigned to the workspace, [this document](https://learn.microsoft.com/en-us/azure/sentinel/roles#microsoft-sentinel-specific-roles) says to assign the roles to the resource group that contains the workspace for best results, which is actually the required scope.

### 3.2. Sentinel interface in Defender portal

All functions of Sentinel are available in the Defender portal

#### 3.2.1. User with permissions to only 1 workspace

The workspace selection is at the top navigation, the navigation shows _All workspaces_ when the user only have access to a single workspace:

<img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/2209c1bf-c231-4252-be99-ca0861a56fb5" />

Clicking on _All workspaces_ just shows the currently accessed workspace:

<img width="1591" height="816" alt="image" src="https://github.com/user-attachments/assets/8fef636b-ba66-4304-bc4d-6b06f622c284" />

#### 3.2.2. User with permissions to multiple workspace

The navigation shows the name of the currently accessed workspace:

<img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/656cdbab-1125-44c9-beee-6e1da5775190" />

Clicking on the workspace name allows the user to change workspace:

<img width="1592" height="816" alt="image" src="https://github.com/user-attachments/assets/3bae8cb4-707a-481c-8dce-f78fe3034f95" />
