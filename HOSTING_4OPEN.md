# Anonymous Hosting via 4open.science (Primary)

This checklist walks a first-time artifact author through publishing a double-blind artifact using anonymous.4open.science.

## 0) Pre-flight (must pass)
- `./tools/anon_scan.sh` reports no findings.
- `./scripts/self_check.sh` succeeds.
- Grep scans for common absolute home-directory prefixes (Unix and Windows) and email patterns return no matches.

If any check fails, fix the issue and re-run before publishing.

## 1) Create a throwaway GitHub account
1) Use a fresh email that is not tied to you or your institution.
2) Create a new GitHub account with:
   - No real name, no avatar, no profile links.
   - No org memberships.
   - A neutral username (e.g., random words).
3) Enable 2FA on the throwaway account.

## 2) Create a throwaway GitHub repository
1) Create a new empty repository under the throwaway account.
2) Use a neutral/random repo name (avoid any project or institution name).
3) Do not add a README, license, or templates (keep it empty).

## 3) Push this repo (HTTPS + PAT only)
1) Create a GitHub Personal Access Token (PAT) under the throwaway account.
   - Minimal scopes: `repo`.
2) Add the remote and push:
   ```bash
   git remote add origin <THROWAWAY_REPO_HTTPS_URL>
   git push -u origin main
   ```
3) Do not store credentials in files; use the Git credential helper if needed.

## 4) Create the anonymous 4open link
1) Go to: https://anonymous.4open.science/
2) Sign in with the throwaway GitHub account.
3) Use the “anonymize” flow:
   - GitHub repo URL: `<THROWAWAY_REPO_HTTPS_URL>`
   - Terms to anonymize: see the list below.
4) Generate the anonymous link:
   - `https://anonymous.4open.science/r/<TOKEN>`

## 5) Terms to anonymize (placeholders)
Provide all strings that could reveal identity. Replace these placeholders with your real sensitive terms:
- `<AUTHOR_NAME_1>`
- `<AUTHOR_NAME_2>`
- `<INSTITUTION_NAME>`
- `<LAB_NAME>`
- `<EMAIL_DOMAIN>`
- `<GITHUB_USERNAME>`
- `<PROJECT_CODENAME>`
- `<PERSONAL_HANDLE>`
- `<PREPRINT_URL>`

Tip: include any names that appear in the paper, acknowledgments, or earlier drafts.

## 6) Verify in an incognito window
1) Open the anonymous link in a private/incognito window.
2) Confirm it does NOT show:
   - Repo owner, account name, org name.
   - Commit author identities.
   - Links to the throwaway account.
3) Confirm required files are accessible:
   - `pom.xml`, `src/`, `REPRODUCE.md`, `QUICKSTART.md`, `OPEN_SCIENCE_APPENDIX.md`.
4) Confirm any binary dependencies needed for build (e.g., `lib/`) are accessible.

## 7) What NOT to do
- Do not use personal or institutional GitHub accounts.
- Do not use SSH keys tied to your identity.
- Do not add analytics, tracking pixels, or external logging.
- Do not use personal websites or self-hosted buckets.

## Optional: 4open CLI (do not run unless comfortable)
If you prefer a local anonymized bundle, the official CLI can generate one:
```bash
npm install -g @tdurieux/anonymous_github
anonymous_github
```
Notes:
- Requires Node/npm and may require GitHub access.
- Generates an anonymized zip based on local config/settings.
