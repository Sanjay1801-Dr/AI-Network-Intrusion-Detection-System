# Configuration Strategy & Security Policies

This directory documents the configuration parameters and secrets management policy for the AI-Based Network Intrusion Detection System.

## 1. Secrets Management Policy
- **Zero Hard-Coded Credentials:** No passwords, database URIs, secret keys, or authentication tokens are ever committed to version control.
- **`.env.example` as Blueprint:** The `.env.example` file in the project root lists every configuration key along with safe default values and descriptive comments.
- **Runtime Injection:** In containerized or production cloud deployments, configuration keys must be supplied via OS environment variables, Kubernetes Secrets, or a vault service (AWS Secrets Manager, HashiCorp Vault).

## 2. Configuration Reference

| Parameter Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | String | `development` | Runtime environment (`development`, `staging`, `production`) |
| `DEBUG` | Boolean | `True` | Enables debug mode and extended error traces |
| `HOST` | String | `127.0.0.1` | Local IP address for ASGI bind |
| `PORT` | Integer | `8000` | Local port for ASGI bind |
| `DATABASE_URL` | String | `sqlite:///./network_ids.db` | SQLAlchemy database connection URI |
| `ALLOWED_ORIGINS` | List[String] | `http://localhost:5173,...` | Comma-separated CORS allowed domains |
| `SECRET_KEY` | String | `[placeholder]` | Cryptographic key for JWT & signature generation |
| `CONFIDENCE_THRESHOLD` | Float | `0.75` | Minimum ML probability required to trigger an alert |
| `ANOMALY_CONTAMINATION` | Float | `0.03` | Expected proportion of outliers in baseline traffic |
| `LOG_LEVEL` | String | `INFO` | Logging threshold (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
