# GitHub Actions Workflow Guide

## Overview

This template includes enhanced GitHub Actions workflows for continuous integration, deployment, and maintenance.

## Workflows

### 1. Build and Deploy (`build.yml`)
**Trigger**: Push to main branch
**Purpose**: Build and deploy to GitHub Pages

This is the main workflow that:
- Builds your book
- Deploys to GitHub Pages
- Handles both legacy and Actions deployment methods

### 2. Validate Build (`validate-build.yml`)
**Trigger**: Pull requests and pushes to main
**Purpose**: Validate changes before merge

Features:
- Jekyll conflict detection
- Configuration validation
- Internal link checking
- Preview server testing
- Build artifact upload

### 3. Deploy Preview (`deploy-preview.yml`)
**Trigger**: Pull requests (opened/updated)
**Purpose**: Deploy PR previews

Features:
- Deploys each PR to a unique preview URL
- Automatically comments preview link on PR
- Updates preview on new commits
- Requires PR from same repository (no forks)

### 4. Scheduled Maintenance (`scheduled-maintenance.yml`)
**Trigger**: Weekly (Mondays 9 AM UTC) or manual
**Purpose**: Regular health checks

Features:
- Dependency updates check
- Security vulnerability scan
- External link validation
- Template version check
- Auto-creates issues for problems

## Configuration

### Enable Workflows

All workflows are in `.github/workflows/`. To enable:

1. Ensure GitHub Actions is enabled in repository settings
2. Workflows activate automatically on their triggers
3. For scheduled workflows, wait for the schedule or run manually

### Disable Workflows

To disable a specific workflow:

1. **Via GitHub UI**:
   - Go to Actions tab
   - Click on the workflow
   - Click "..." menu → Disable workflow

2. **Via Configuration**:
   ```yaml
   # Add to the workflow file
   on:
     workflow_dispatch: # Only manual trigger
   ```

3. **Delete the file**:
   ```bash
   rm .github/workflows/workflow-name.yml
   ```

## PR Preview Deployment

### How It Works

1. Developer creates a pull request
2. Workflow builds the book with modified baseurl
3. Deploys to `gh-pages` branch under `/pr-preview/pr-{number}/`
4. Comments on PR with preview link
5. Updates on each new commit

### Preview URL Format
```text
https://{owner}.github.io/{repo}/pr-preview/pr-{number}/
```

### Requirements
- PR must be from the same repository (not forks)
- Repository must have GitHub Pages enabled
- `gh-pages` branch must exist or be creatable

### Cleanup
PR previews are automatically cleaned up when PRs are closed/merged.

## Security Considerations

### Workflow Permissions

Workflows use minimal required permissions:
- `contents: read` - Read repository
- `pages: write` - Deploy to Pages
- `pull-requests: write` - Comment on PRs
- `issues: write` - Create maintenance issues

### Secrets

No additional secrets required. Workflows use:
- `GITHUB_TOKEN` - Automatically provided
- Repository permissions - Inherited from settings

### Fork PRs

PR preview deployment is disabled for fork PRs to prevent:
- Unauthorized deployments
- Secret exposure
- Resource abuse

## Troubleshooting

### Workflow Not Running

1. Check Actions is enabled in repository settings
2. Verify workflow file syntax
3. Check trigger conditions match your action
4. Review Actions tab for error messages

### Preview Deployment Fails

1. Ensure GitHub Pages is enabled
2. Check `gh-pages` branch permissions
3. Verify no baseurl conflicts
4. Check PR is from same repository

### Scheduled Workflow Issues

1. Cron syntax must be valid
2. Scheduled workflows disable after 60 days of inactivity
3. Manual trigger with `workflow_dispatch` to test

### Link Checker Timeouts

External link checking may timeout for:
- Sites with rate limiting
- Slow responding servers
- Authentication required

Adjust timeout in workflow:
```yaml
linkinator docs --timeout 60000  # 60 seconds
```

## Best Practices

### 1. Workflow Optimization
- Use `actions/cache` for dependencies
- Run jobs in parallel when possible
- Use `continue-on-error` for non-critical steps
- Set reasonable timeouts

### 2. PR Previews
- Clean up old previews regularly
- Limit preview retention
- Monitor `gh-pages` branch size
- Use preview for visual changes

### 3. Maintenance
- Review scheduled job outputs weekly
- Update dependencies monthly
- Address security warnings promptly
- Keep workflows simple and focused

## Customization

### Add Status Badges

Add to your README.md:
```markdown
![Build Status](https://github.com/{owner}/{repo}/workflows/Build%20and%20Deploy/badge.svg)
![Validation](https://github.com/{owner}/{repo}/workflows/Validate%20Build/badge.svg)
```

### Custom Notifications

Add Slack/Email notifications:
```yaml
- name: Notify Slack
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### Matrix Builds

Test across multiple versions:
```yaml
strategy:
  matrix:
    node-version: [16, 18, 20]
    os: [ubuntu-latest, windows-latest]
```

## Migration from v2

If upgrading from template v2:

1. Remove old workflows:
   ```bash
   rm .github/workflows/content-validation.yml
   rm .github/workflows/quality-checks.yml
   ```

2. Copy new workflows from template
3. Update any custom modifications
4. Test with a PR before merging

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [Actions Marketplace](https://github.com/marketplace?type=actions)
- [Security Best Practices](https://docs.github.com/en/actions/security-guides)
