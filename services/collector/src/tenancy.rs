use client_intel_core::sha256_hex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct KeyEntry {
    tenant: String,
    hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct Tenancy {
    site_keys: Vec<KeyEntry>,
    admin_keys: Vec<KeyEntry>,
}

impl Tenancy {
    pub fn new(site_keys: &[(String, String)], admin_keys: &[(String, String)]) -> Self {
        Self {
            site_keys: site_keys
                .iter()
                .map(|(tenant, key)| KeyEntry {
                    tenant: tenant.clone(),
                    hash: sha256_hex(key),
                })
                .collect(),
            admin_keys: admin_keys
                .iter()
                .map(|(tenant, key)| KeyEntry {
                    tenant: tenant.clone(),
                    hash: sha256_hex(key),
                })
                .collect(),
        }
    }

    pub fn site_keys_required(&self) -> bool {
        !self.site_keys.is_empty()
    }

    pub fn admin_keys_required(&self) -> bool {
        !self.admin_keys.is_empty()
    }

    pub fn resolve_site(&self, key: Option<&str>) -> Option<String> {
        if self.site_keys.is_empty() {
            return Some("local".to_string());
        }
        self.resolve(&self.site_keys, key?)
    }

    pub fn resolve_admin(&self, key: Option<&str>) -> Option<String> {
        if self.admin_keys.is_empty() {
            return Some("*".to_string());
        }
        self.resolve(&self.admin_keys, key?)
    }

    fn resolve(&self, entries: &[KeyEntry], key: &str) -> Option<String> {
        let hash = sha256_hex(key);
        entries
            .iter()
            .find(|entry| constant_time_eq(entry.hash.as_bytes(), hash.as_bytes()))
            .map(|entry| entry.tenant.clone())
    }

    pub fn tenants(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for entry in self.site_keys.iter().chain(self.admin_keys.iter()) {
            *counts.entry(entry.tenant.clone()).or_insert(0) += 1;
        }
        counts
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_mode_uses_local_and_global_scopes() {
        let tenancy = Tenancy::default();
        assert_eq!(tenancy.resolve_site(None).as_deref(), Some("local"));
        assert_eq!(tenancy.resolve_admin(None).as_deref(), Some("*"));
    }

    #[test]
    fn resolves_only_matching_tenant_keys() {
        let tenancy = Tenancy::new(
            &[("alpha".to_string(), "site-alpha".to_string())],
            &[("alpha".to_string(), "admin-alpha".to_string())],
        );

        assert_eq!(
            tenancy.resolve_site(Some("site-alpha")).as_deref(),
            Some("alpha")
        );
        assert_eq!(
            tenancy.resolve_admin(Some("admin-alpha")).as_deref(),
            Some("alpha")
        );
        assert!(tenancy.resolve_site(Some("wrong")).is_none());
        assert!(tenancy.resolve_admin(None).is_none());
    }
}
