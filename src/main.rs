use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use lazy_static::lazy_static;
use regex::Regex;
use sequoia_net::wkd;
use sequoia_openpgp::{
    cert::Cert,
    parse::Parse,
    policy::{Policy, StandardPolicy},
};
use serde::{Deserialize, Serialize};
use std::{env, fs::File};

async fn get_cert(email: &str, req_client: &reqwest::Client) -> Result<Cert> {
    Ok(Cert::from_bytes(
        &req_client
            .get(
                wkd::Url::from(email)
                    .context("Failed to parse email address")?
                    .to_url(wkd::Variant::Advanced)
                    .context("Failed to build wkd url")?,
            )
            .send()
            .await
            .context("Failed to send GET request")?
            .error_for_status()
            .context("WKD server returned error")?
            .bytes()
            .await
            .context("Failed to get response")?,
    )
    .context("Failed to parse certificate")?)
}

async fn get_days_to_expiration(
    email: &str,
    req_client: &reqwest::Client,
    pgp_policy: &dyn Policy,
    now: DateTime<Utc>,
) -> Result<Option<i64>> {
    Ok(get_cert(email, req_client)
        .await
        .context("Failed to get certificate")?
        .keys()
        .with_policy(pgp_policy, Some(now.into()))
        .revoked(false)
        .filter_map(|key| {
            key.key_expiration_time()
                .map(|t| (DateTime::<Utc>::from(t) - now).num_days())
        })
        .min())
}

#[derive(Debug, Deserialize, Serialize)]
struct KeyInfo {
    email: String,
    days_to_expiration: Result<Option<i64>, String>,
}

fn get_state_filename() -> Result<String> {
    Ok(format!(
        "{}/pgp_expiration",
        env::var("MUNIN_PLUGSTATE").context("Failed to get env MUNIN_PLUGSTATE")?
    ))
}

async fn cron() -> Result<Vec<KeyInfo>> {
    // fetch data to state file

    let req_client = reqwest::Client::new();
    let pgp_policy = &StandardPolicy::new();
    let now: DateTime<Utc> = Utc::now();

    let emails = env::var("emails")
        .context("Failed to get env emails")?
        .split(' ')
        .map(|s| s.to_owned())
        .collect::<Vec<_>>();
    let results = stream::iter(emails)
        .then(|email| async {
            let days_to_expiration = get_days_to_expiration(&email, &req_client, pgp_policy, now)
                .await
                .map_err(|e| format!("Error: {:#}", e));
            KeyInfo {
                email,
                days_to_expiration,
            }
        })
        .collect::<Vec<_>>()
        .await;

    ron::ser::to_writer_pretty(
        File::create(get_state_filename()?).context("Failed to create state file")?,
        &results,
        ron::ser::PrettyConfig::new(),
    )
    .context("Failed to write state file")?;

    Ok(results)
}

async fn get_results() -> Result<Vec<KeyInfo>> {
    Ok(match File::open(get_state_filename()?) {
        Ok(f) => ron::de::from_reader(f).context("Failed to read state file")?,
        Err(_) => cron().await?,
    })
}

fn clean_fieldname(text: &str) -> String {
    // http://guide.munin-monitoring.org/en/latest/develop/plugins/howto-write-plugins.html#python-plugin
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(^[^A-Za-z_]|[^A-Za-z0-9_])").unwrap();
    }
    RE.replace_all(text, "_").to_string()
}

async fn config() -> Result<()> {
    let results = get_results().await?;

    println!(
        "graph_title OpenPGP key expiration
graph_vlabel days to expiration"
    );

    for key_info in results {
        let days_to_expiration: Result<(), String> = match key_info.days_to_expiration {
            Ok(days_to_expiration) => match days_to_expiration {
                Some(_) => Ok(()),
                None => continue,
            },
            Err(e) => Err(e),
        };
        let fieldname = clean_fieldname(&key_info.email);
        println!(
            "_{fieldname}.label {email}
_{fieldname}.warning 14:
_{fieldname}.critical 7:",
            fieldname = fieldname,
            email = key_info.email,
        );
        if let Err(e) = days_to_expiration {
            println!("_{}.extinfo {}", fieldname, e);
        }
    }

    Ok(())
}

async fn fetch() -> Result<()> {
    let results = get_results().await?;

    for key_info in results {
        let days_to_expiration = match key_info.days_to_expiration {
            Ok(days_to_expiration) => match days_to_expiration {
                Some(days_to_expiration) => days_to_expiration,
                None => continue,
            },
            Err(_) => -999,
        };
        println!(
            "_{fieldname}.value {value}",
            fieldname = clean_fieldname(&key_info.email),
            value = days_to_expiration,
        );
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args();
    match args.len() {
        2 => match args.nth(1).unwrap().as_str() {
            "config" => {
                config().await?;
                if env::var("MUNIN_CAP_DIRTYCONFIG").unwrap_or_default() == "1" {
                    fetch().await?;
                }
            }
            "cron" => {
                cron().await?;
            }
            _ => {
                fetch().await?;
            }
        },
        _ => {
            fetch().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_fieldname() {
        assert_eq!(
            clean_fieldname("foo.bar@example.com"),
            "foo_bar_example_com"
        );
    }
}
