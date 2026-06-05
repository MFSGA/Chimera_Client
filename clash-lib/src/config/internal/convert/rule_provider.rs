use std::collections::HashMap;

use crate::{
    common::utils::{encode_hex, sha256},
    config::{
        def,
        internal::config::{
            FileRuleProvider, HttpRuleProvider, InlineRuleProvider, RuleProviderDef,
        },
    },
};

pub(super) fn convert(
    before: Option<HashMap<String, def::RuleProviderDef>>,
) -> HashMap<String, RuleProviderDef> {
    before
        .unwrap_or_default()
        .into_iter()
        .map(|(name, provider)| {
            let converted = match provider {
                def::RuleProviderDef::Http(http) => {
                    let path = http
                        .path
                        .unwrap_or_else(|| cache_path_for_key(http.url.as_bytes()));
                    RuleProviderDef::Http(HttpRuleProvider {
                        url: http.url,
                        interval: http.interval,
                        behavior: http.behavior,
                        path,
                        format: http.format,
                        inline_rules: http.inline_rules,
                    })
                }
                def::RuleProviderDef::File(file) => {
                    RuleProviderDef::File(FileRuleProvider {
                        path: file.path,
                        interval: file.interval,
                        behavior: file.behavior,
                        format: file.format,
                        inline_rules: file.inline_rules,
                    })
                }
                def::RuleProviderDef::Inline(inline) => {
                    let path = inline
                        .path
                        .unwrap_or_else(|| cache_path_for_key(name.as_bytes()));
                    RuleProviderDef::Inline(InlineRuleProvider {
                        path,
                        behavior: inline.behavior,
                        inline_rules: inline.inline_rules,
                    })
                }
            };
            (name, converted)
        })
        .collect()
}

fn cache_path_for_key(key: &[u8]) -> String {
    let hash = sha256(key);
    format!("rules/{}", encode_hex(&hash[..16]))
}
