use client_intel_core::{
    compare_observations, ClientResolution, ClientSummary, Fingerprints, MatchResult, Observation,
    ResolutionKind,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    postgres: Option<PgPool>,
    memory: Arc<RwLock<HashMap<Uuid, Observation>>>,
}

#[derive(Debug, Clone)]
struct Candidate {
    observation_id: Uuid,
    client_id: Uuid,
    fingerprints: Fingerprints,
}

impl Store {
    pub async fn connect(database_url: Option<&str>) -> Result<Self, sqlx::Error> {
        let postgres = match database_url {
            Some(database_url) => {
                let pool = PgPoolOptions::new()
                    .max_connections(20)
                    .connect(database_url)
                    .await?;
                sqlx::raw_sql(include_str!("../../../migrations/001_init.sql"))
                    .execute(&pool)
                    .await?;
                sqlx::raw_sql(include_str!("../../../migrations/002_client_graph.sql"))
                    .execute(&pool)
                    .await?;
                Some(pool)
            }
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

    pub async fn resolve_client(
        &self,
        tenant_id: &str,
        fingerprints: &Fingerprints,
        window_days: u32,
        candidate_limit: i64,
        match_threshold: f32,
        min_confidence: f32,
    ) -> Result<ClientResolution, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(window_days as i64);
        let mut candidates = Vec::new();
        let mut seen = HashSet::new();

        {
            let memory = self.memory.read().await;
            let mut values = memory
                .values()
                .filter(|observation| {
                    observation.tenant_id == tenant_id && observation.created_at >= cutoff
                })
                .collect::<Vec<_>>();
            values.sort_by_key(|observation| std::cmp::Reverse(observation.created_at));

            for observation in values.into_iter().take(candidate_limit.max(0) as usize) {
                if seen.insert(observation.id) {
                    candidates.push(Candidate {
                        observation_id: observation.id,
                        client_id: observation.client_id,
                        fingerprints: observation.fingerprints.clone(),
                    });
                }
            }
        }

        if let Some(pool) = &self.postgres {
            let rows = sqlx::query(
                r#"
                SELECT id, client_id, fingerprints
                FROM observations
                WHERE tenant_id = $1
                  AND created_at >= $2
                  AND client_id IS NOT NULL
                ORDER BY created_at DESC
                LIMIT $3
                "#,
            )
            .bind(tenant_id)
            .bind(cutoff)
            .bind(candidate_limit)
            .fetch_all(pool)
            .await?;

            for row in rows {
                let id: Uuid = row.try_get("id")?;
                if !seen.insert(id) {
                    continue;
                }
                let client_id: Uuid = row.try_get("client_id")?;
                let value: serde_json::Value = row.try_get("fingerprints")?;
                if let Ok(candidate_fingerprints) = serde_json::from_value(value) {
                    candidates.push(Candidate {
                        observation_id: id,
                        client_id,
                        fingerprints: candidate_fingerprints,
                    });
                }
            }
        }

        let mut scored = candidates
            .into_iter()
            .map(|candidate| {
                let result = compare_observations(fingerprints, &candidate.fingerprints);
                (candidate, result)
            })
            .filter(|(_, result)| result.available_weight > 0.0)
            .collect::<Vec<_>>();

        scored.sort_by(|(_, left), (_, right)| {
            graph_score(right)
                .partial_cmp(&graph_score(left))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let Some((best_candidate, best_match)) = scored.first() else {
            let client_id = Uuid::new_v4();
            return Ok(ClientResolution {
                kind: ResolutionKind::NewClient,
                client_id,
                ..ClientResolution::default()
            });
        };

        let qualifies = best_match.same_client_probability >= match_threshold
            && best_match.confidence >= min_confidence;

        if !qualifies {
            let client_id = Uuid::new_v4();
            return Ok(ClientResolution {
                kind: ResolutionKind::NewClient,
                client_id,
                probability: best_match.same_client_probability,
                confidence: best_match.confidence,
                matching_components: best_match.matching_components.clone(),
                conflicting_components: best_match.conflicting_components.clone(),
                ..ClientResolution::default()
            });
        }

        let ambiguous = scored.get(1).is_some_and(|(second_candidate, second_match)| {
            second_candidate.client_id != best_candidate.client_id
                && second_match.same_client_probability >= match_threshold
                && second_match.confidence >= min_confidence
                && (graph_score(best_match) - graph_score(second_match)).abs() < 0.04
        });

        if ambiguous {
            let client_id = Uuid::new_v4();
            return Ok(ClientResolution {
                kind: ResolutionKind::Ambiguous,
                client_id,
                probability: best_match.same_client_probability,
                confidence: best_match.confidence,
                matched_observation_id: Some(best_candidate.observation_id),
                matching_components: best_match.matching_components.clone(),
                conflicting_components: best_match.conflicting_components.clone(),
            });
        }

        Ok(ClientResolution {
            kind: ResolutionKind::MatchedClient,
            client_id: best_candidate.client_id,
            probability: best_match.same_client_probability,
            confidence: best_match.confidence,
            matched_observation_id: Some(best_candidate.observation_id),
            matching_components: best_match.matching_components.clone(),
            conflicting_components: best_match.conflicting_components.clone(),
        })
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
        let resolution = serde_json::to_value(&observation.resolution).unwrap_or_default();
        let raw = serde_json::to_value(&observation.raw).unwrap_or_default();
        let document = serde_json::to_value(observation).unwrap_or_default();

        let mut transaction = pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO observations (
                id, tenant_id, client_id, created_at, source_ip, user_agent, http_version,
                tls, http, browser, fingerprints, profile, resolution, raw, document
            ) VALUES (
                $1, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            ON CONFLICT (id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                client_id = EXCLUDED.client_id,
                browser = EXCLUDED.browser,
                fingerprints = EXCLUDED.fingerprints,
                profile = EXCLUDED.profile,
                resolution = EXCLUDED.resolution,
                raw = EXCLUDED.raw,
                document = EXCLUDED.document
            "#,
        )
        .bind(observation.id)
        .bind(&observation.tenant_id)
        .bind(observation.client_id)
        .bind(observation.created_at)
        .bind(observation.connection.remote_ip.as_deref())
        .bind(observation.http.user_agent.as_deref())
        .bind(&observation.http.version)
        .bind(tls)
        .bind(http)
        .bind(browser)
        .bind(fingerprints.clone())
        .bind(profile.clone())
        .bind(resolution)
        .bind(raw)
        .bind(document)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO clients (
                tenant_id, client_id, first_seen, last_seen, observation_count,
                latest_profile, latest_fingerprints
            ) VALUES ($1, $2, $3, $3, 1, $4, $5)
            ON CONFLICT (tenant_id, client_id) DO UPDATE SET
                last_seen = GREATEST(clients.last_seen, EXCLUDED.last_seen),
                first_seen = LEAST(clients.first_seen, EXCLUDED.first_seen),
                observation_count = clients.observation_count + 1,
                latest_profile = EXCLUDED.latest_profile,
                latest_fingerprints = EXCLUDED.latest_fingerprints
            "#,
        )
        .bind(&observation.tenant_id)
        .bind(observation.client_id)
        .bind(observation.created_at)
        .bind(profile)
        .bind(fingerprints)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
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

        sqlx::query(
            r#"
            DELETE FROM clients c
            WHERE NOT EXISTS (
                SELECT 1 FROM observations o
                WHERE o.tenant_id = c.tenant_id AND o.client_id = c.client_id
            )
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get(
        &self,
        id: Uuid,
        tenant_id: Option<&str>,
    ) -> Result<Option<Observation>, sqlx::Error> {
        if let Some(observation) = self.memory.read().await.get(&id).cloned() {
            if tenant_id.is_none_or(|tenant| observation.tenant_id == tenant) {
                return Ok(Some(observation));
            }
            return Ok(None);
        }

        let Some(pool) = &self.postgres else {
            return Ok(None);
        };

        let row = match tenant_id {
            Some(tenant) => {
                sqlx::query(
                    r#"
                    SELECT document
                    FROM observations
                    WHERE id = $1 AND tenant_id = $2
                    "#,
                )
                .bind(id)
                .bind(tenant)
                .fetch_optional(pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"
                    SELECT document
                    FROM observations
                    WHERE id = $1
                    "#,
                )
                .bind(id)
                .fetch_optional(pool)
                .await?
            }
        };

        let Some(row) = row else {
            return Ok(None);
        };

        let document: serde_json::Value = row.try_get("document")?;
        Ok(serde_json::from_value(document).ok())
    }

    pub async fn get_client(
        &self,
        tenant_id: Option<&str>,
        client_id: Uuid,
    ) -> Result<Option<ClientSummary>, sqlx::Error> {
        if self.postgres.is_none() {
            let memory = self.memory.read().await;
            let mut observations = memory
                .values()
                .filter(|observation| {
                    observation.client_id == client_id
                        && tenant_id.is_none_or(|tenant| observation.tenant_id == tenant)
                })
                .cloned()
                .collect::<Vec<_>>();
            observations.sort_by_key(|observation| observation.created_at);
            let Some(first) = observations.first() else {
                return Ok(None);
            };
            let latest = observations.last().expect("non-empty observations");
            return Ok(Some(ClientSummary {
                tenant_id: first.tenant_id.clone(),
                client_id,
                first_seen: Some(first.created_at),
                last_seen: Some(latest.created_at),
                observation_count: observations.len() as u64,
                latest_profile: Some(latest.profile.clone()),
                latest_fingerprints: Some(latest.fingerprints.clone()),
                recent_observation_ids: observations
                    .iter()
                    .rev()
                    .take(50)
                    .map(|observation| observation.id)
                    .collect(),
            }));
        }

        let pool = self.postgres.as_ref().expect("postgres checked above");
        let client_row = match tenant_id {
            Some(tenant) => sqlx::query(
                r#"
                SELECT tenant_id, first_seen, last_seen, observation_count,
                       latest_profile, latest_fingerprints
                FROM clients
                WHERE tenant_id = $1 AND client_id = $2
                "#,
            )
            .bind(tenant)
            .bind(client_id)
            .fetch_optional(pool)
            .await?,
            None => sqlx::query(
                r#"
                SELECT tenant_id, first_seen, last_seen, observation_count,
                       latest_profile, latest_fingerprints
                FROM clients
                WHERE client_id = $1
                ORDER BY last_seen DESC
                LIMIT 1
                "#,
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?,
        };

        let Some(row) = client_row else {
            return Ok(None);
        };
        let resolved_tenant: String = row.try_get("tenant_id")?;
        let ids = sqlx::query(
            r#"
            SELECT id
            FROM observations
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY created_at DESC
            LIMIT 50
            "#,
        )
        .bind(&resolved_tenant)
        .bind(client_id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .filter_map(|row| row.try_get::<Uuid, _>("id").ok())
        .collect();

        let latest_profile = row
            .try_get::<serde_json::Value, _>("latest_profile")
            .ok()
            .and_then(|value| serde_json::from_value(value).ok());
        let latest_fingerprints = row
            .try_get::<serde_json::Value, _>("latest_fingerprints")
            .ok()
            .and_then(|value| serde_json::from_value(value).ok());

        Ok(Some(ClientSummary {
            tenant_id: resolved_tenant,
            client_id,
            first_seen: row.try_get("first_seen").ok(),
            last_seen: row.try_get("last_seen").ok(),
            observation_count: row.try_get::<i64, _>("observation_count").unwrap_or(0).max(0) as u64,
            latest_profile,
            latest_fingerprints,
            recent_observation_ids: ids,
        }))
    }
}

fn graph_score(result: &MatchResult) -> f32 {
    result.same_client_probability * (0.55 + result.confidence * 0.45)
}
