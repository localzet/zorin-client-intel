use client_intel_core::Observation;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    postgres: Option<PgPool>,
    memory: Arc<RwLock<HashMap<Uuid, Observation>>>,
}

impl Store {
    pub async fn connect(database_url: Option<&str>) -> Result<Self, sqlx::Error> {
        let postgres = match database_url {
            Some(database_url) => Some(
                PgPoolOptions::new()
                    .max_connections(10)
                    .connect(database_url)
                    .await?,
            ),
            None => None,
        };

        Ok(Self {
            postgres,
            memory: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn backend_name(&self) -> &'static str {
        if self.postgres.is_some() {
            "postgres"
        } else {
            "memory"
        }
    }

    pub async fn save(&self, observation: &Observation) -> Result<(), sqlx::Error> {
        self.memory
            .write()
            .await
            .insert(observation.id, observation.clone());

        let Some(pool) = &self.postgres else {
            return Ok(());
        };

        let tls = serde_json::to_value(&observation.connection.tls).unwrap_or_default();
        let http = serde_json::to_value(&observation.http).unwrap_or_default();
        let browser = serde_json::to_value(&observation.browser).unwrap_or_default();
        let fingerprints = serde_json::to_value(&observation.fingerprints).unwrap_or_default();
        let profile = serde_json::to_value(&observation.profile).unwrap_or_default();
        let raw = serde_json::to_value(&observation.raw).unwrap_or_default();
        let document = serde_json::to_value(observation).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT INTO observations (
                id, created_at, source_ip, user_agent, http_version,
                tls, http, browser, fingerprints, profile, raw, document
            ) VALUES (
                $1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12
            )
            ON CONFLICT (id) DO UPDATE SET
                browser = EXCLUDED.browser,
                fingerprints = EXCLUDED.fingerprints,
                profile = EXCLUDED.profile,
                raw = EXCLUDED.raw,
                document = EXCLUDED.document
            "#,
        )
        .bind(observation.id)
        .bind(observation.created_at)
        .bind(observation.connection.remote_ip.as_deref())
        .bind(observation.http.user_agent.as_deref())
        .bind(&observation.http.version)
        .bind(tls)
        .bind(http)
        .bind(browser)
        .bind(fingerprints)
        .bind(profile)
        .bind(raw)
        .bind(document)
        .execute(pool)
        .await?;

        Ok(())
    }


    pub async fn purge_older_than(&self, days: u32) -> Result<u64, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);

        self.memory
            .write()
            .await
            .retain(|_, observation| observation.created_at >= cutoff);

        let Some(pool) = &self.postgres else {
            return Ok(0);
        };

        let result = sqlx::query(
            r#"
            DELETE FROM observations
            WHERE created_at < $1
            "#,
        )
        .bind(cutoff)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get(&self, id: Uuid) -> Result<Option<Observation>, sqlx::Error> {
        if let Some(observation) = self.memory.read().await.get(&id).cloned() {
            return Ok(Some(observation));
        }

        let Some(pool) = &self.postgres else {
            return Ok(None);
        };

        let row = sqlx::query(
            r#"
            SELECT document
            FROM observations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let document: serde_json::Value = row.try_get("document")?;
        Ok(serde_json::from_value(document).ok())
    }
}
