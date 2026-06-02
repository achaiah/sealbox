use anyhow::{Context, Result};
use reqwest::Client;
use sealbox_server::{
    crypto::{
        data_key::DataKey,
        master_key::{PrivateMasterKey, PublicMasterKey},
    },
    repo::{MasterKey, Secret},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;

use crate::{SecretCommands, config::Config, output::OutputManager};

use super::secret_archive;

pub struct DecryptedSecret {
    pub key: String,
    pub value: String,
    pub version: i32,
    pub expires_at: Option<i64>,
    pub metadata: Option<String>,
}

pub async fn handle_command(command: SecretCommands, config: &Config) -> Result<()> {
    let output = OutputManager::new(config.output.format.clone());

    match command {
        SecretCommands::Set { key, value, ttl } => {
            set_secret(config, &output, key, value, ttl).await
        }
        SecretCommands::Get { key, version } => get_secret(config, &output, key, version).await,
        SecretCommands::Delete { key, version } => {
            delete_secret(config, &output, key, version).await
        }
        SecretCommands::List => list_secrets(config, &output).await,
        SecretCommands::History { key } => get_secret_history(config, &output, key).await,
        SecretCommands::Import { file, format } => {
            secret_archive::import_secrets(config, &output, file, format).await
        }
        SecretCommands::Export { file, keys, format } => {
            secret_archive::export_secrets(config, &output, file, keys, format).await
        }
    }
}

async fn set_secret(
    config: &Config,
    output: &OutputManager,
    key: String,
    value: Option<String>,
    ttl: Option<i64>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    // Get secret value
    let secret_value = match value {
        Some(val) => val,
        None => {
            output.print_info("Enter secret value (input will be hidden):");
            rpassword::read_password().context("Failed to read secret value")?
        }
    };

    if secret_value.trim().is_empty() {
        anyhow::bail!("Secret value cannot be empty");
    }

    save_secret_value(config, output, key, secret_value, ttl, None).await
}

async fn fetch_active_master_key(config: &Config) -> Result<MasterKey> {
    let client = Client::new();
    let response = client
        .get(format!("{}/v1/master-key/active", config.server.url))
        .bearer_auth(&config.server.token)
        .send()
        .await
        .context("Failed to request active master key")?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to get error information".to_string());
        anyhow::bail!(
            "Server returned error while fetching active master key (status code: {}):\n{}",
            status,
            error_body
        );
    }

    response
        .json()
        .await
        .context("Failed to parse active master key response")
}

fn load_private_key(config: &Config) -> Result<PrivateMasterKey> {
    let private_key_path = config
        .keys
        .private_key_path
        .to_str()
        .context("Private key path contains invalid characters")?;

    let private_key_pem =
        std::fs::read_to_string(private_key_path).context("Failed to read private key file")?;

    PrivateMasterKey::from_str(&private_key_pem).context("Failed to parse private key")
}

async fn get_secret(
    config: &Config,
    output: &OutputManager,
    key: String,
    version: Option<i32>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    output.print_info("Fetching and decrypting secret...");

    let decrypted = fetch_decrypted_secret(config, &key, version).await?;

    output.print_secret(
        &decrypted.key,
        &decrypted.value,
        Some(decrypted.version),
        decrypted.expires_at,
    )?;
    Ok(())
}

pub async fn save_secret_value(
    config: &Config,
    output: &OutputManager,
    key: String,
    secret_value: String,
    ttl: Option<i64>,
    metadata: Option<String>,
) -> Result<()> {
    output.print_info("Fetching active master key...");

    let master_key = fetch_active_master_key(config).await?;
    let public_key = PublicMasterKey::from_str(&master_key.public_key)
        .context("Failed to parse active master public key")?;
    let data_key = DataKey::new();
    let encrypted_data = data_key
        .encrypt(secret_value.as_bytes())
        .context("Failed to encrypt secret locally")?;
    let encrypted_data_key = public_key
        .encrypt(data_key.as_bytes())
        .context("Failed to encrypt data key")?;

    output.print_info("Saving encrypted secret to server...");

    let payload = json!({
        "encrypted_data": encrypted_data,
        "encrypted_data_key": encrypted_data_key,
        "master_key_id": master_key.id,
        "ttl": ttl,
        "metadata": metadata
    });

    let client = Client::new();
    let response = client
        .put(format!("{}/v1/secrets/{}", config.server.url, key))
        .bearer_auth(&config.server.token)
        .json(&payload)
        .send()
        .await
        .context("Failed to request server")?;

    let status = response.status();
    if status.is_success() {
        let result: Value = response
            .json()
            .await
            .context("Failed to parse server response")?;

        output.print_success(&format!("Secret '{key}' saved successfully!"));
        output.print_value(&result)?;
    } else {
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

    Ok(())
}

pub async fn fetch_decrypted_secret(
    config: &Config,
    key: &str,
    version: Option<i32>,
) -> Result<DecryptedSecret> {
    config
        .validate()
        .context("Configuration validation failed")?;

    let mut url = format!("{}/v1/secrets/{}", config.server.url, key);
    if let Some(v) = version {
        url.push_str(&format!("?version={v}"));
    }

    let client = Client::new();
    let response = client
        .get(&url)
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

    let secret_data: Secret = response
        .json()
        .await
        .context("Failed to parse server response")?;

    let private_key = load_private_key(config)?;

    // Decrypt the data key using RSA private key
    let decrypted_data_key = private_key
        .decrypt(&secret_data.encrypted_data_key)
        .context("Failed to decrypt data key with RSA private key")?;

    // Use the data key to decrypt the secret data
    let data_key = sealbox_server::crypto::data_key::DataKey::from_bytes(&decrypted_data_key)
        .context("Invalid data key format")?;

    let decrypted_bytes = data_key
        .decrypt(&secret_data.encrypted_data)
        .context("Failed to decrypt secret data")?;

    let decrypted_value =
        String::from_utf8(decrypted_bytes).context("Decrypted data is not valid UTF-8")?;

    Ok(DecryptedSecret {
        key: secret_data.key,
        value: decrypted_value,
        version: secret_data.version,
        expires_at: secret_data.expires_at,
        metadata: secret_data.metadata,
    })
}

async fn delete_secret(
    config: &Config,
    output: &OutputManager,
    key: String,
    version: i32,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    let url = format!(
        "{}/v1/secrets/{}?version={}",
        config.server.url, key, version
    );

    output.print_info(&format!("Deleting secret '{key}' version {version}..."));

    let client = Client::new();
    let response = client
        .delete(&url)
        .bearer_auth(&config.server.token)
        .send()
        .await
        .context("Failed to request server")?;

    let status = response.status();
    if status.is_success() {
        output.print_success(&format!(
            "Secret '{key}' version {version} deleted successfully!"
        ));
    } else {
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

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ListSecretsResponse {
    secrets: Vec<sealbox_server::repo::SecretInfo>,
}

async fn list_secrets(config: &Config, output: &OutputManager) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    output.print_info("Fetching secret list...");

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

    if result.secrets.is_empty() {
        output.print_info("No secrets found");
    } else {
        output.print_secret_infos(&result.secrets)?;
    }

    Ok(())
}

async fn get_secret_history(_config: &Config, output: &OutputManager, key: String) -> Result<()> {
    // Note: Current server API doesn't directly support version history listing, this is a reserved feature
    output.print_warning("Server does not currently support viewing secret version history");
    output.print_info(&format!(
        "To get a specific version of the secret, use: sealbox secret get {key} --version <N>"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutputFormat;
    use tempfile::TempDir;

    fn create_test_config() -> (Config, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = Config::default();
        config.keys.public_key_path = temp_dir.path().join("public.pem");
        config.keys.private_key_path = temp_dir.path().join("private.pem");
        config.server.token = "test-token".to_string();
        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_set_secret_empty_value() {
        let (config, _temp_dir) = create_test_config();
        let output = OutputManager::new(OutputFormat::Json);

        let result = set_secret(
            &config,
            &output,
            "test-key".to_string(),
            Some("".to_string()),
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Secret value cannot be empty")
        );
    }

    #[test]
    fn test_load_private_key_missing_file() {
        let (config, _temp_dir) = create_test_config();

        let result = load_private_key(&config);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private key file"));
    }
}
