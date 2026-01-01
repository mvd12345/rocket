# Open Science Appendix (Double-Blind)

## Artifact Contents
- Source code in `src/main` and optional tests in `src/test`.
- Default configs in `src/main/resources/config`.
- Local SootUp dependencies in `lib/` (system-scoped by Maven).
- Demo inputs in `demo/` (no generated outputs are included).

## What Is Omitted (and Why)
- Build outputs such as `target/`, `out/`, and prebuilt JARs (`jar_file/`).
- Generated analysis results (e.g., `demo/output`).
- Any CI configuration or external service integration.

These omissions reduce the risk of identity leakage and ensure a clean, reproducible build.

## Blind Hosting Guidance
- Use a blind-review hosting service such as anonymous.4open.science or an equivalent option.
- Avoid self-managed hosting, analytics, or any tracking scripts.
- Do not include repository history or remote URLs.

## Artifact Links (to be filled before submission)
Anonymous URLs should be included in the paper’s Open Science appendix.

- Primary anonymous URL: `https://anonymous.4open.science/r/<TOKEN>`
- Backup bundle zip filename: `artifact_source.zip`
- Backup bundle zip SHA256: `<SHA256_FOR_ZIP>`
- Backup bundle tar.gz filename: `artifact_source.tar.gz`
- Backup bundle tar.gz SHA256: `<SHA256_FOR_TAR_GZ>`

## Reviewer Checklist
- Build: `mvn -q -DskipTests package`
- Test: `mvn -q test`
- Run: `./scripts/self_check.sh`
