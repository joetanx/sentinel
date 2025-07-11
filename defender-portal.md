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

For reference, when a new user with no roles assigned logs in to the Defender portal, the view is similar to below:

<img width="1592" height="817" alt="image" src="https://github.com/user-attachments/assets/5a4cbef8-971e-4cbd-8d9e-f126154f7825" />

Since this user does not have any rights to any workspace in the environment, no workspace is visible in the Defender portal:

<img width="1592" height="800" alt="image" src="https://github.com/user-attachments/assets/c2b972e0-0fba-409b-815a-d853f8446873" />

## 2. Connecting a workspace to Defender portal
