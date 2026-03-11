use std::{collections::HashMap, sync::Arc};

static DOMAIN_STEP: &str = ".";
static COMPLEX_WILDCARD: &str = "+";
static DOT_WILDCARD: &str = "";
static WILDCARD: &str = "*";

pub struct Node<T> {
    children: HashMap<String, Node<T>>,
    data: Option<Arc<T>>,
}

impl<T> Default for Node<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Node<T> {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            data: None,
        }
    }

    pub fn get_data(&self) -> Option<&T> {
        self.data.as_deref()
    }

    pub fn get_child(&self, key: &str) -> Option<&Self> {
        self.children.get(key)
    }

    pub fn get_child_mut(&mut self, key: &str) -> Option<&mut Self> {
        self.children.get_mut(key)
    }

    pub fn has_child(&self, key: &str) -> bool {
        self.get_child(key).is_some()
    }

    pub fn add_child(&mut self, key: &str, child: Node<T>) {
        self.children.insert(key.to_string(), child);
    }
}

pub struct StringTrie<T> {
    root: Node<T>,
}

impl<T> Default for StringTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> StringTrie<T> {
    pub fn new() -> Self {
        Self { root: Node::new() }
    }

    pub fn insert(&mut self, domain: &str, data: Arc<T>) -> bool {
        let (parts, valid) = valid_and_split_domain(domain);
        if !valid {
            return false;
        }

        let mut parts = parts.unwrap();
        match parts[0] {
            part if part == COMPLEX_WILDCARD => {
                self.insert_inner(&parts[1..], data.clone());
                parts[0] = DOT_WILDCARD;
                self.insert_inner(&parts, data);
            }
            _ => self.insert_inner(&parts, data),
        }

        true
    }

    pub fn search(&self, domain: &str) -> Option<&Node<T>> {
        let (parts, valid) = valid_and_split_domain(domain);
        if !valid {
            return None;
        }

        let parts = parts.unwrap();
        if parts[0].is_empty() {
            return None;
        }

        if let Some(node) = Self::search_inner(&self.root, parts)
            && node.data.is_some()
        {
            return Some(node);
        }

        None
    }

    fn insert_inner(&mut self, parts: &[&str], data: Arc<T>) {
        let mut node = &mut self.root;

        for index in (0..parts.len()).rev() {
            let part = parts[index];
            if !node.has_child(part) {
                node.add_child(part, Node::new());
            }

            node = node.get_child_mut(part).expect("child just inserted");
        }

        node.data = Some(data);
    }

    fn search_inner<'a>(node: &'a Node<T>, parts: Vec<&str>) -> Option<&'a Node<T>> {
        if parts.is_empty() {
            return Some(node);
        }

        if let Some(child) = node.get_child(parts.last().expect("non-empty parts"))
            && let Some(found) =
                Self::search_inner(child, parts[..parts.len() - 1].into())
            && found.data.is_some()
        {
            return Some(found);
        }

        if let Some(child) = node.get_child(WILDCARD)
            && let Some(found) =
                Self::search_inner(child, parts[..parts.len() - 1].into())
            && found.data.is_some()
        {
            return Some(found);
        }

        node.get_child(DOT_WILDCARD)
    }
}

pub fn valid_and_split_domain(domain: &str) -> (Option<Vec<&str>>, bool) {
    if !domain.is_empty() && domain.ends_with('.') {
        return (None, false);
    }

    let parts: Vec<&str> = domain.split(DOMAIN_STEP).collect();
    if parts.len() == 1 {
        if parts[0].is_empty() {
            return (None, false);
        }
        return (Some(parts), true);
    }

    for part in parts.iter().skip(1) {
        if part.is_empty() {
            return (None, false);
        }
    }

    (Some(parts), true)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use super::StringTrie;

    static LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    #[test]
    fn test_basic() {
        let mut tree = StringTrie::new();

        let domains = ["example.com", "google.com", "localhost"];

        for domain in domains {
            assert!(tree.insert(domain, Arc::new(LOCAL_IP)));
        }

        let node = tree
            .search("example.com")
            .expect("should match example.com");
        assert_eq!(node.get_data(), Some(&LOCAL_IP));
        assert!(!tree.insert("", Arc::new(LOCAL_IP)));
        assert!(tree.search("").is_none());
        assert!(tree.search("localhost").is_some());
        assert!(tree.search("www.google.com").is_none());
    }

    #[test]
    fn test_wildcard() {
        let mut tree = StringTrie::new();

        let domains = [
            "*.example.com",
            "sub.*.example.com",
            "*.dev",
            ".org",
            ".example.net",
            ".apple.*",
            "+.foo.com",
            "+.stun.*.*",
            "+.stun.*.*.*",
            "+.stun.*.*.*.*",
            "stun.l.google.com",
        ];

        for domain in domains {
            assert!(tree.insert(domain, Arc::new(LOCAL_IP)));
        }

        assert!(tree.search("sub.example.com").is_some());
        assert!(tree.search("sub.foo.example.com").is_some());
        assert!(tree.search("test.org").is_some());
        assert!(tree.search("test.example.net").is_some());
        assert!(tree.search("test.apple.com").is_some());
        assert!(tree.search("foo.com").is_some());
        assert!(tree.search("global.stun.website.com").is_some());

        assert!(tree.search("foo.sub.example.com").is_none());
        assert!(tree.search("foo.example.dev").is_none());
        assert!(tree.search("example.com").is_none());
    }

    #[test]
    fn test_priority() {
        let mut tree = StringTrie::new();

        let domains = [".dev", "example.dev", "*.example.dev", "test.example.dev"];

        for (index, domain) in domains.iter().enumerate() {
            assert!(tree.insert(domain, Arc::new(index)));
        }

        let assert_match = |domain: &str| -> Arc<usize> {
            tree.search(domain)
                .expect("domain should match")
                .data
                .clone()
                .expect("node should have data")
        };

        assert_eq!(assert_match("test.dev"), Arc::new(0));
        assert_eq!(assert_match("foo.bar.dev"), Arc::new(0));
        assert_eq!(assert_match("example.dev"), Arc::new(1));
        assert_eq!(assert_match("foo.example.dev"), Arc::new(2));
        assert_eq!(assert_match("test.example.dev"), Arc::new(3));
    }

    #[test]
    fn test_boundary() {
        let mut tree = StringTrie::new();

        assert!(tree.insert("*.dev", Arc::new(LOCAL_IP)));
        assert!(!tree.insert(".", Arc::new(LOCAL_IP)));
        assert!(!tree.insert("..dev", Arc::new(LOCAL_IP)));
        assert!(tree.search("dev").is_none());
    }

    #[test]
    fn test_wildcard_boundary() {
        let mut tree = StringTrie::new();

        assert!(tree.insert("+.*", Arc::new(LOCAL_IP)));
        assert!(tree.insert("stun.*.*.*", Arc::new(LOCAL_IP)));

        assert!(tree.search("example.com").is_some());
    }
}
