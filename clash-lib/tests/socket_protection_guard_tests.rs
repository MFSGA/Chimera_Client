use std::{fs, path::Path};

use syn::{
    Attribute, Expr, ExprCall, ImplItemFn, ItemFn, ItemImpl, ItemMod, Meta, Token,
    TraitItemFn,
    parse::Parser,
    punctuated::Punctuated,
    visit::{self, Visit},
};

const TEST_ONLY_SOURCE_PREFIXES: &[&str] =
    &["clash-lib/src/proxy/utils/test_utils/"];

#[derive(Clone, Copy)]
enum ForbiddenCall {
    TcpConnect,
    UdpBind,
}

impl ForbiddenCall {
    fn type_name(self) -> &'static str {
        match self {
            Self::TcpConnect => "TcpStream",
            Self::UdpBind => "UdpSocket",
        }
    }

    fn method_name(self) -> &'static str {
        match self {
            Self::TcpConnect => "connect",
            Self::UdpBind => "bind",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::TcpConnect => "TcpStream::connect",
            Self::UdpBind => "UdpSocket::bind",
        }
    }
}

#[test]
fn proxy_runtime_tcp_connects_use_socket_helper() {
    assert_no_forbidden_runtime_usage(ForbiddenCall::TcpConnect);
}

#[test]
fn proxy_runtime_udp_binds_use_socket_helper() {
    assert_no_forbidden_runtime_usage(ForbiddenCall::UdpBind);
}

fn assert_no_forbidden_runtime_usage(forbidden: ForbiddenCall) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("workspace root");
    let source_root = manifest_dir.join("src/proxy");
    let mut violations = Vec::new();

    visit_rs_files(&source_root, &mut |path| {
        let rel = path
            .strip_prefix(workspace_root)
            .expect("path should be under workspace")
            .to_string_lossy()
            .replace('\\', "/");

        if TEST_ONLY_SOURCE_PREFIXES
            .iter()
            .any(|prefix| rel.starts_with(prefix))
        {
            return;
        }

        let source = fs::read_to_string(path).expect("read source file");
        let calls = find_forbidden_runtime_calls(&source, forbidden)
            .unwrap_or_else(|error| panic!("failed to parse {rel}: {error}"));
        for call in calls {
            violations.push(format!("{rel}: {call}"));
        }
    });

    assert!(
        violations.is_empty(),
        "runtime proxy code must use socket_helpers instead of {}; violations:\n{}",
        forbidden.display_name(),
        violations.join("\n")
    );
}

fn find_forbidden_runtime_calls(
    source: &str,
    forbidden: ForbiddenCall,
) -> syn::Result<Vec<String>> {
    let file = syn::parse_file(source)?;
    if attributes_require_test(&file.attrs) {
        return Ok(Vec::new());
    }

    let mut visitor = RuntimeCallVisitor {
        forbidden,
        violations: Vec::new(),
    };
    visitor.visit_file(&file);
    Ok(visitor.violations)
}

struct RuntimeCallVisitor {
    forbidden: ForbiddenCall,
    violations: Vec<String>,
}

impl<'ast> Visit<'ast> for RuntimeCallVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if attributes_require_test(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if attributes_require_test(&node.attrs) {
            return;
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if attributes_require_test(&node.attrs) {
            return;
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if attributes_require_test(&node.attrs) {
            return;
        }
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if attributes_require_test(&node.attrs) {
            return;
        }
        visit::visit_trait_item_fn(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(function) = node.func.as_ref()
            && path_ends_with_call(
                &function.path,
                self.forbidden.type_name(),
                self.forbidden.method_name(),
            )
        {
            self.violations
                .push(self.forbidden.display_name().to_owned());
        }
        visit::visit_expr_call(self, node);
    }
}

fn path_ends_with_call(
    path: &syn::Path,
    type_name: &str,
    method_name: &str,
) -> bool {
    let mut segments = path.segments.iter().rev();
    segments
        .next()
        .is_some_and(|segment| segment.ident == method_name)
        && segments
            .next()
            .is_some_and(|segment| segment.ident == type_name)
}

fn attributes_require_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(attribute_requires_test)
}

fn attribute_requires_test(attribute: &Attribute) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }

    let Meta::List(list) = &attribute.meta else {
        return false;
    };
    syn::parse2::<Meta>(list.tokens.clone())
        .map(|condition| cfg_condition_requires_test(&condition))
        .unwrap_or(false)
}

fn cfg_condition_requires_test(condition: &Meta) -> bool {
    match condition {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => parse_cfg_children(list)
            .is_some_and(|children| {
                children.iter().any(cfg_condition_requires_test)
            }),
        Meta::List(list) if list.path.is_ident("any") => parse_cfg_children(list)
            .is_some_and(|children| {
                !children.is_empty()
                    && children.iter().all(cfg_condition_requires_test)
            }),
        Meta::List(_) | Meta::NameValue(_) => false,
    }
}

fn parse_cfg_children(list: &syn::MetaList) -> Option<Vec<Meta>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .map(|children| children.into_iter().collect())
}

fn visit_rs_files(dir: &Path, f: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(dir).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            f(&path);
        }
    }
}

#[test]
fn guard_ignores_cfg_test_and_cfg_all_test_modules() {
    let source = r#"
        #[cfg(test)]
        mod tests {
            fn direct_connect() {
                let _ = TcpStream::connect("127.0.0.1:1");
            }
        }

        #[cfg(all(test, feature = "example"))]
        mod feature_tests {
            fn direct_bind() {
                let _ = UdpSocket::bind("127.0.0.1:0");
            }
        }
    "#;

    assert!(
        find_forbidden_runtime_calls(source, ForbiddenCall::TcpConnect)
            .unwrap()
            .is_empty()
    );
    assert!(
        find_forbidden_runtime_calls(source, ForbiddenCall::UdpBind)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn guard_does_not_ignore_cfg_not_test_code() {
    let source = r#"
        #[cfg(not(test))]
        fn runtime_connect() {
            let _ = tokio::net::TcpStream::connect("127.0.0.1:1");
        }
    "#;

    assert_eq!(
        find_forbidden_runtime_calls(source, ForbiddenCall::TcpConnect)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn guard_detects_fully_qualified_runtime_calls() {
    let source = r#"
        fn runtime_networking() {
            let _ = tokio::net::TcpStream::connect("127.0.0.1:1");
            let _ = std::net::UdpSocket::bind("127.0.0.1:0");
        }
    "#;

    assert_eq!(
        find_forbidden_runtime_calls(source, ForbiddenCall::TcpConnect)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        find_forbidden_runtime_calls(source, ForbiddenCall::UdpBind)
            .unwrap()
            .len(),
        1
    );
}
