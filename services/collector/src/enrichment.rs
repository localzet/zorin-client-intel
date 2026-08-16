use client_intel_core::NetworkEnrichment;
use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
struct EnrichmentRecord {
    cidr: IpNet,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    network_type: Option<String>,
    #[serde(default)]
    is_hosting: Option<bool>,
    #[serde(default)]
    is_mobile: Option<bool>,
    #[serde(default)]
    is_vpn: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_confidence")]
    confidence: f32,
}

fn default_confidence() -> f32 {
    0.80
}

#[derive(Debug, Clone, Default)]
pub struct EnrichmentDb {
    records: Vec<EnrichmentRecord>,
    source_path: Option<String>,
}

impl EnrichmentDb {
    pub fn load(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = path else {
            return Ok(Self::default());
        };

        let content = fs::read_to_string(path)?;
        let mut records: Vec<EnrichmentRecord> = serde_json::from_str(&content)?;
        records.sort_by_key(|record| std::cmp::Reverse(record.cidr.prefix_len()));

        Ok(Self {
            records,
            source_path: Some(path.display().to_string()),
        })
    }

    pub fn enabled(&self) -> bool {
        !self.records.is_empty()
    }

    pub fn source_path(&self) -> Option<&str> {
        self.source_path.as_deref()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<NetworkEnrichment> {
        let record = self.records.iter().find(|record| record.cidr.contains(&ip))?;

        Some(NetworkEnrichment {
            source: record
                .source
                .clone()
                .or_else(|| self.source_path.clone())
                .or_else(|| Some("local-cidr-db".to_string())),
            country_code: record.country_code.clone(),
            country: record.country.clone(),
            region: record.region.clone(),
            city: record.city.clone(),
            latitude: record.latitude,
            longitude: record.longitude,
            timezone: record.timezone.clone(),
            asn: record.asn,
            organization: record.organization.clone(),
            network_type: record.network_type.clone(),
            is_hosting: record.is_hosting,
            is_mobile: record.is_mobile,
            is_vpn: record.is_vpn,
            is_proxy: record.is_proxy,
            is_tor: record.is_tor,
            tags: record.tags.clone(),
            confidence: record.confidence.clamp(0.0, 1.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_record_wins() {
        let mut records = vec![
            EnrichmentRecord {
                    cidr: "203.0.113.128/25".parse().expect("CIDR"),
                    source: Some("narrow".to_string()),
                    country_code: Some("DE".to_string()),
                    country: None,
                    region: None,
                    city: None,
                    latitude: None,
                    longitude: None,
                    timezone: None,
                    asn: None,
                    organization: None,
                    network_type: None,
                    is_hosting: None,
                    is_mobile: None,
                    is_vpn: None,
                    is_proxy: None,
                    is_tor: None,
                    tags: Vec::new(),
                    confidence: 0.9,
            },
            EnrichmentRecord {
                    cidr: "203.0.113.0/24".parse().expect("CIDR"),
                    source: Some("wide".to_string()),
                    country_code: Some("US".to_string()),
                    country: None,
                    region: None,
                    city: None,
                    latitude: None,
                    longitude: None,
                    timezone: None,
                    asn: None,
                    organization: None,
                    network_type: None,
                    is_hosting: None,
                    is_mobile: None,
                    is_vpn: None,
                    is_proxy: None,
                    is_tor: None,
                    tags: Vec::new(),
                    confidence: 0.8,
            },
        ];
        records.sort_by_key(|record| std::cmp::Reverse(record.cidr.prefix_len()));
        let db = EnrichmentDb {
            records,
            source_path: None,
        };

        let result = db
            .lookup("203.0.113.200".parse().expect("IP"))
            .expect("enrichment");
        assert_eq!(result.source.as_deref(), Some("narrow"));
        assert_eq!(result.country_code.as_deref(), Some("DE"));
    }
}
