# ☁️ Cloud SOC Demo — PowerShell + GitHub Actions

This project simulates a lightweight **Security Operations Center** in the cloud:

- **Synthetic cloud logs** (CloudTrail-like JSON) auto-generated with PowerShell.  
- **Detection engine** flags suspicious events (IAM abuse, abnormal IPs).  
- **Structured alerts** (JSON schema with severity + category).  
- **CI/CD automation** via GitHub Actions (runs daily, produces alerts).  
- **Live dashboard** on GitHub Pages → [View Dashboard](https://<username>.github.io/cloud-soc-demo/).  

## Architecture
```mermaid
flowchart TD
    A[Generate Logs] --> B[Detect Rules]
    B --> C[alerts.json]
    C --> D[GitHub Actions Artifact]
    C --> E[GitHub Pages Dashboard]
