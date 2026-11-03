//! Canonical JSON for digests that are persisted or compared across releases.
//!
//! `serde_json` orders object keys by its `preserve_order` feature, which any
//! dependency can enable through Cargo feature unification. Digests must not
//! change with the dependency graph, so they hash objects with keys sorted
//! recursively: exactly the bytes `serde_json` writes without that feature.
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

/// `value` with every object's keys in sorted order, recursively.
pub fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&map[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The canonical JSON bytes of `value`, independent of `preserve_order`.
pub fn to_vec(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&sorted(&serde_json::to_value(value)?))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_hash_with_sorted_keys_at_every_depth() {
        // Insertion order deliberately unsorted: with `preserve_order` enabled,
        // plain serialization would keep it.
        let mut inner = serde_json::Map::new();
        inner.insert("z".into(), Value::from(1));
        inner.insert("a".into(), Value::from(2));
        let mut outer = serde_json::Map::new();
        outer.insert("version".into(), Value::from(2));
        outer.insert("environment".into(), Value::Object(inner.clone()));
        outer.insert("list".into(), Value::Array(vec![Value::Object(inner)]));
        assert_eq!(
            String::from_utf8(to_vec(&Value::Object(outer)).unwrap()).unwrap(),
            r#"{"environment":{"a":2,"z":1},"list":[{"a":2,"z":1}],"version":2}"#
        );
    }
}
