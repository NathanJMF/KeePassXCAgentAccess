# Keeper

Keeper is a Linux desktop and tray app for managing KeePass vaults and giving agents scoped access. You decide which entries an agent can use and what it can do with them.

![Keeper showing all entries across the selected synthetic vault](docs/screenshots/vaults.png)

## Quick Start

On Ubuntu GNOME, clone this repository and run one of these commands from the checkout.

| Setup | Command |
| --- | --- |
| Desktop app and tray icon | `./install` |
| Desktop app, broker, and isolated agent runner | `./install --agent` |

1. Open **Keeper** and select **Add Vault…** to open an existing KeePass database.
2. To remember a vault password, select **Remember on This Device**. Keeper stores it in the OS keyring.
3. For agent access, configure your agent client with the runner command printed by the installer and give it the [Keeper skill](skills/keepassxc-agent-access/SKILL.md). Open **Access** to review requests for entries and permissions.

## Agent Access

Expand a token to see which vaults, groups, and entries it covers. Open its details to review requested permissions, or disable or remove a token you previously approved. Use **Pause Agent Access** to stop agents from using their tokens.

![Keeper's Agent Access view showing pending and approved requests and an expanded token scope](docs/screenshots/access.png)

## Activity

See which agent acted, which resource it used, and what happened. Expand related events for their history or double-click an event for details and its audit note. Approved credential actions can authenticate to configured HTTPS destinations without returning passwords to the agent.

![Keeper's Activity view showing grouped audit events, affected resources, and outcomes](docs/screenshots/activity.png)

The screenshots use disposable vaults and synthetic agent activity.

## Updates and Help

- **Update** from **Keeper Settings → Updates** using **Check for Updates**, then **Apply Update**.
- **Uninstall** with `./uninstall`. Your vault files and settings are kept.
- See the [User Guide](docs/guide.md) for vault management, approval settings, runner setup, and synthetic testing.
