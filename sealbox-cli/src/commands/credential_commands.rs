use anyhow::{Context, Result};
use reqwest::Client;
use sealbox_server::repo::SecretInfo;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    CredentialCommands,
    config::Config,
    output::OutputManager,
    secret_commands::{fetch_decrypted_secret, save_secret_value},
};

use super::input::read_secret_from_tty_or_stdin;

#[derive(Debug, Deserialize, Serialize)]
struct CredentialSecret {
    #[serde(rename = "type")]
    credential_type: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CredentialMetadata {
    #[serde(rename = "type")]
    credential_type: String,
    username: String,
}

#[derive(Debug, Deserialize)]
struct ListSecretsResponse {
    secrets: Vec<SecretInfo>,
}

pub async fn handle_command(command: CredentialCommands, config: &Config) -> Result<()> {
    let output = OutputManager::new(config.output.format.clone());

    match command {
        CredentialCommands::Set { key, username, ttl } => {
            set_credential(config, &output, key, username, ttl).await
        }
        CredentialCommands::Get { key, version } => {
            get_credential(config, &output, key, version).await
        }
        CredentialCommands::List { username } => list_credentials(config, &output, username).await,
    }
}

async fn set_credential(
    config: &Config,
    output: &OutputManager,
    key: String,
    username: String,
    ttl: Option<i64>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    if username.trim().is_empty() {
        anyhow::bail!("Username cannot be empty");
    }

    let password = read_secret_from_tty_or_stdin(
        output,
        "Enter password (input will be hidden):",
        "password",
    )?;
    if password.trim().is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let credential = CredentialSecret {
        credential_type: "credential".to_string(),
        username: username.clone(),
        password,
    };
    let metadata = CredentialMetadata {
        credential_type: "credential".to_string(),
        username,
    };

    save_secret_value(
        config,
        output,
        key,
        serde_json::to_string(&credential).context("Failed to serialize credential")?,
        ttl,
        Some(serde_json::to_string(&metadata).context("Failed to serialize credential metadata")?),
    )
    .await
}

async fn get_credential(
    config: &Config,
    output: &OutputManager,
    key: String,
    version: Option<i32>,
) -> Result<()> {
    let decrypted = fetch_decrypted_secret(config, &key, version).await?;
    let credential: CredentialSecret =
        serde_json::from_str(&decrypted.value).context("Secret is not a credential payload")?;

    output.print_value(&json!({
        "key": decrypted.key,
        "version": decrypted.version,
        "expires_at": decrypted.expires_at,
        "username": credential.username,
        "password": credential.password,
        "metadata": decrypted.metadata,
    }))
}

async fn list_credentials(
    config: &Config,
    output: &OutputManager,
    username_filter: Option<String>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    let client = Client::new();
    let response = client
        .get(format!("{}/v1/secrets", config.server.url))
        .bearer_auth(&config.server.token)
        .send()
        .await
        .context("Failed to request server")?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to get error information".to_string());
        anyhow::bail!(
            "Server returned error (status code: {}):\n{}",
            status,
            error_body
        );
    }

    let result: ListSecretsResponse = response
        .json()
        .await
        .context("Failed to parse server response")?;
    let normalized_filter = username_filter.map(|filter| filter.to_lowercase());
    let credentials = result
        .secrets
        .into_iter()
        .filter_map(|secret| {
            let metadata = secret.metadata.as_deref()?;
            let credential_metadata: CredentialMetadata = serde_json::from_str(metadata).ok()?;
            if credential_metadata.credential_type != "credential" {
                return None;
            }
            if let Some(filter) = &normalized_filter
                && !credential_metadata.username.to_lowercase().contains(filter)
            {
                return None;
            }
            Some(json!({
                "key": secret.key,
                "version": secret.version,
                "username": credential_metadata.username,
                "expires_at": secret.expires_at,
            }))
        })
        .collect::<Vec<_>>();

    if credentials.is_empty() {
        output.print_info("No credentials found");
    } else {
        output.print_value(&json!(credentials))?;
    }

    Ok(())
}
