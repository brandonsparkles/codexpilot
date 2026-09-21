//! Fork-local, provider-scoped model-picker blocklist.
//!
//! Some providers surface models in their catalog that this fork does not
//! want offered in the picker. That filtering used to live in
//! `codex_protocol::openai_models`, inside `impl From<ModelInfo> for
//! ModelPreset` — a shared upstream conversion that *every* provider's
//! catalog flows through, so a Copilot-only intent silently hid the models
//! globally and guaranteed a merge conflict on the next upstream pull.
//!
//! It lives here instead: applied once per catalog build, after the presets
//! exist and before the default preset is recomputed, and only for the
//! provider it was meant for.
//!
//! The patterns are **not** hardcoded model ids. They are read from
//! [`PICKER_BLOCKLIST_ENV`] when the manager is constructed, as a
//! comma-separated list of case-insensitive substrings matched against each
//! preset's model id and display name:
//!
//! ```sh
//! export CODEX_PICKER_BLOCKLIST='claude-sonnet-4-5,sonnet 4.5'
//! ```
//!
//! Unset or empty means "block nothing", which is the upstream behavior.

use codex_protocol::openai_models::ModelPreset;

/// Environment variable holding the comma-separated blocklist spec.
pub const PICKER_BLOCKLIST_ENV: &str = "CODEX_PICKER_BLOCKLIST";

/// Case-insensitive substring patterns that hide a model from the picker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PickerBlocklist {
    patterns: Vec<String>,
}

impl PickerBlocklist {
    /// Build the blocklist for `provider_id`.
    ///
    /// Returns an empty blocklist for any provider other than the one the
    /// spec is scoped to, so a provider-specific preference can never leak
    /// into another provider's catalog.
    pub fn for_provider(provider_id: &str, scoped_to: &str) -> Self {
        if provider_id != scoped_to {
            return Self::default();
        }
        match std::env::var(PICKER_BLOCKLIST_ENV) {
            Ok(spec) => Self::from_spec(&spec),
            Err(_) => Self::default(),
        }
    }

    /// Parse a comma-separated spec. Blank entries are ignored.
    pub fn from_spec(spec: &str) -> Self {
        Self {
            patterns: spec
                .split(',')
                .map(|pattern| pattern.trim().to_ascii_lowercase())
                .filter(|pattern| !pattern.is_empty())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Clear `show_in_picker` on every preset the blocklist matches.
    ///
    /// Must run before `ModelPreset::mark_default_by_picker_visibility`,
    /// which picks the first picker-visible preset as the default — a hidden
    /// model must not be able to become the default.
    pub fn apply(&self, presets: &mut [ModelPreset]) {
        if self.is_empty() {
            return;
        }
        for preset in presets.iter_mut() {
            if self.hides(preset) {
                preset.show_in_picker = false;
            }
        }
    }

    fn hides(&self, preset: &ModelPreset) -> bool {
        let model = preset.model.to_ascii_lowercase();
        let display_name = preset.display_name.to_ascii_lowercase();
        self.patterns
            .iter()
            .any(|pattern| model.contains(pattern) || display_name.contains(pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::openai_models::ReasoningEffort;

    fn preset(model: &str, display_name: &str) -> ModelPreset {
        ModelPreset {
            id: model.to_string(),
            model: model.to_string(),
            display_name: display_name.to_string(),
            description: String::new(),
            default_reasoning_effort: ReasoningEffort::None,
            supported_reasoning_efforts: Vec::new(),
            supports_personality: false,
            is_default: false,
            upgrade: None,
            show_in_picker: true,
            availability_nux: None,
            supported_in_api: true,
            input_modalities: Vec::new(),
        }
    }

    #[test]
    fn empty_spec_blocks_nothing() {
        let blocklist = PickerBlocklist::from_spec("  , ,");
        assert!(blocklist.is_empty());

        let mut presets = vec![preset("some-model", "Some Model")];
        blocklist.apply(&mut presets);
        assert!(presets[0].show_in_picker);
    }

    #[test]
    fn spec_hides_matching_model_id_or_display_name() {
        let blocklist = PickerBlocklist::from_spec("blocked-slug, Blocked Name ");

        let mut presets = vec![
            preset("blocked-slug-20991231", "Something Else"),
            preset("other-model", "Blocked Name v2"),
            preset("kept-model", "Kept Model"),
        ];
        blocklist.apply(&mut presets);

        assert!(!presets[0].show_in_picker);
        assert!(!presets[1].show_in_picker);
        assert!(
            presets[2].show_in_picker,
            "unrelated models must stay visible"
        );
    }

    #[test]
    fn other_providers_get_an_empty_blocklist() {
        // Scoped to a provider the caller is not using: no env read matters.
        let blocklist = PickerBlocklist::for_provider("openai", "github-copilot");
        assert!(blocklist.is_empty());
    }
}
