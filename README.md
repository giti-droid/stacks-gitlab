# stacks-gitlab

Compose fuer den Stack `gitlab_2026_sept` — nur den Dienst `gitlab`.

**Wahrheit ist dieses Repo.** Es wird per Push-Mirror nach GitHub
(privat) gespiegelt, damit Portainer GitLab deployen kann, ohne dass GitLab
dafuer laufen muss.

## Ablauf eines Updates

1. Renovate legt hier einen MR an (Label `gitlab`, kein Automerge).
2. In Pulse unter *Container-Updates* auf **Starten**:
   1. MR mergen, Push-Mirror anstossen
   2. **Vorpruefung:** SHA `main` GitLab == SHA `main` GitHub, sonst Abbruch
   3. Portainer-Redeploy des Stacks `gitlab_2026_sept`
   4. Nachkontrolle: Container `running`/`healthy`
   5. **Nachpruefung:** von Portainer deployter Commit == SHA GitLab, sonst
      ERR-Alarm
3. Pulse vergleicht die beiden SHAs zusaetzlich laufend (Check
   `github-mirror`). Abweichung -> Mirror-Sync, nach 60 s erneut pruefen,
   dann Alarm.

## Nicht hier

- Runner: `gitmi/stacks` -> `docker/gitlab_runner`
- MCP: `gitmi/stacks` -> `docker/mcp_gitlab` (einzige Variable
  `GITLAB_OAUTH_APP_ID`)

## Portainer

Source `stacks_github` (GitHub, Lese-Token), Compose path `compose.yml`,
Reference `refs/heads/main`, **GitOps-Polling aus**.
