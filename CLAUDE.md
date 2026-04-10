# Development Workflow

- NEVER commit directly to `main`. Always create a feature branch first.
- Branch protection is enabled — pushes to `main` will be rejected.
- Flow: feature branch → PR to main → merge → auto-deploy staging → approve → production
- Deploys are managed by the centralized orchestrator at github.com/mnemom/deploy
- If you accidentally started work on main, recover with:
  ```bash
  git checkout -b fix/your-description
  git push -u origin fix/your-description
  gh pr create --base main
  ```

## Deploy Guardrails

### Allowed
- Trigger staging deploys: `gh workflow run deploy.yml --repo mnemom/deploy -f repos=mnemom-platform -f environment=staging`
- Check deploy status: `gh run list --repo mnemom/deploy --workflow deploy.yml --limit 5`
- Roll back staging gateway: `gh workflow run rollback.yml --repo mnemom/deploy -f service=gateway -f environment=staging`
- Roll back staging observer: `gh workflow run rollback.yml --repo mnemom/deploy -f service=observer -f environment=staging`

### Not allowed
- Approve or trigger production deploys (enforced by GitHub environment protection)
- Roll back production without explicit human instruction
- Modify deploy workflows in the deploy repo
