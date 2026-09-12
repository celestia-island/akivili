use serde::{Deserialize, Serialize};

use crate::manifest::ResourceEntry;

/// The result of feeding a [`HostAcceptance`](crate::HostAcceptance) to the
/// registry: the ordered series of resources the declaring host should
/// load, one by one.
///
/// Ordering: by entry `order` ascending, ties broken by plugin id, then by
/// manifest position (stable).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceFeed {
    pub items: Vec<FeedItem>,
}

/// One fed resource: which plugin it came from, the manifest entry, the
/// entry's index inside that manifest (for
/// [`Registry::load`](crate::Registry::load)), and the resolved content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedItem {
    pub plugin_id: String,
    pub plugin_version: String,
    /// Index of this entry in the plugin manifest's `resources` vector.
    pub entry_index: usize,
    pub entry: ResourceEntry,
    pub resolved: ResolvedPayload,
}

/// Feed-time-resolved resource content.
///
/// File payloads are read (and digested) when the feed is built, so hosts
/// always see the bytes they were audited against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedPayload {
    /// Inline JSON content (as declared in the manifest).
    Inline(serde_json::Value),
    /// File content read at feed time, with the freshly computed digest.
    File { bytes: Vec<u8>, sha256: String },
}

impl ResolvedPayload {
    /// The payload digest where one applies (`None` for inline JSON).
    pub fn sha256(&self) -> Option<&str> {
        match self {
            ResolvedPayload::Inline(_) => None,
            ResolvedPayload::File { sha256, .. } => Some(sha256),
        }
    }
}

impl ResourceFeed {
    /// Iterates the fed items in feed order.
    pub fn iter(&self) -> std::slice::Iter<'_, FeedItem> {
        self.items.iter()
    }

    /// Number of fed items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether nothing was fed.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Consumes the feed into its items.
    pub fn into_items(self) -> Vec<FeedItem> {
        self.items
    }
}

impl<'a> IntoIterator for &'a ResourceFeed {
    type Item = &'a FeedItem;
    type IntoIter = std::slice::Iter<'a, FeedItem>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl IntoIterator for ResourceFeed {
    type Item = FeedItem;
    type IntoIter = std::vec::IntoIter<FeedItem>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::ResourceKind;

    fn item(plugin_id: &str, order: i32) -> FeedItem {
        FeedItem {
            plugin_id: plugin_id.into(),
            plugin_version: "1.0.0".into(),
            entry_index: 0,
            entry: ResourceEntry {
                kind: ResourceKind::new(crate::kinds::WEBUI_THEME).unwrap(),
                name: None,
                order,
                payload: crate::manifest::Payload::Inline(serde_json::json!({})),
            },
            resolved: ResolvedPayload::Inline(serde_json::json!({})),
        }
    }

    #[test]
    fn feed_iter_and_len() {
        let feed = ResourceFeed {
            items: vec![item("a", 1), item("b", 2)],
        };
        assert_eq!(feed.len(), 2);
        assert!(!feed.is_empty());
        let ids: Vec<&str> = feed.iter().map(|i| i.plugin_id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        let owned: Vec<String> = feed.into_items().into_iter().map(|i| i.plugin_id).collect();
        assert_eq!(owned, ["a", "b"]);
    }

    #[test]
    fn resolved_payload_digest_only_for_files() {
        let inline = ResolvedPayload::Inline(serde_json::json!({ "a": 1 }));
        assert!(inline.sha256().is_none());
        let file = ResolvedPayload::File {
            bytes: b"x".to_vec(),
            sha256: "abc".into(),
        };
        assert_eq!(file.sha256(), Some("abc"));
    }
}
