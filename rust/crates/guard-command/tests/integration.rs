//! Every integration test file in this directory, compiled as one binary.
//!
//! Each file used to link its own executable, and linking a hundred of them
//! dominated the CI test job. nextest still runs every test in its own
//! process. A new test file must be declared here, or listed as its own
//! `[[test]]` target in Cargo.toml when it needs a separate process.

mod business_command_properties;
mod business_gmail_plain;
mod business_gmail_transfer;
mod business_gmail_wire;
mod business_gws_command;
mod business_input_properties;
mod business_mime_properties;
mod business_transfer_properties;
mod command_compatibility;
mod compatibility_safe_scope;
mod data_flow_rules_parity;
mod effect_decision_parity;
mod fd_execution_boundaries;
mod inline_expression_boundaries;
mod js_semver_vectors;
mod manifest_change_vectors;
mod mcp_package_sources;
mod package_context_vectors;
mod portable_command_source_fixtures;
mod pretool_agent_metadata;
mod pretool_bun_eval;
mod pretool_contained_script_tests;
mod pretool_contained_tests;
mod pretool_contained_wrappers;
mod pretool_cwd_compounds;
mod pretool_env_prefix_controls;
mod pretool_file_copies;
mod pretool_file_mutations;
mod pretool_file_reads;
mod pretool_forged_worktree;
mod pretool_generic;
mod pretool_generic_powershell;
mod pretool_git_branch_listing;
mod pretool_git_cd_reads;
mod pretool_git_context_boundaries;
mod pretool_git_execution_environment;
mod pretool_git_filter_batches;
mod pretool_git_filter_config;
mod pretool_git_global_config;
mod pretool_git_hash_object;
mod pretool_git_helper_config;
mod pretool_git_large_listing;
mod pretool_git_nested_repositories;
mod pretool_git_outside_cwd;
mod pretool_git_pager_config;
mod pretool_git_read_sequences;
mod pretool_git_ref_reads;
mod pretool_git_session_ops;
mod pretool_git_submodules;
mod pretool_git_textconv_config;
mod pretool_git_worktree;
mod pretool_git_worktree_session;
mod pretool_github_reads;
mod pretool_grep_repository_metadata;
mod pretool_guard_diagnostics;
mod pretool_home_aliases;
mod pretool_home_cd;
mod pretool_home_layout_reads;
mod pretool_linked_writes;
mod pretool_links_removals;
mod pretool_lockfile_install;
mod pretool_lookup_reads;
mod pretool_metadata_reads;
mod pretool_native_home_writes;
mod pretool_npm_reads;
mod pretool_omp_agent_listing;
mod pretool_omp_artifact_search;
mod pretool_omp_eval_read_helpers;
mod pretool_omp_fp_proofs;
mod pretool_omp_home_documents;
mod pretool_omp_tools;
mod pretool_omp_yield_reports;
mod pretool_pi_tools;
mod pretool_private_temporary_workspace;
mod pretool_prompt_negation_scope;
mod pretool_prompt_secret_requests;
mod pretool_pytest_contained_route;
mod pretool_recursive_copies;
mod pretool_recursive_file_search;
mod pretool_rust_version_probe;
mod pretool_search_data;
mod pretool_skill_listings;
mod pretool_skill_roots;
mod pretool_stdin_filters;
mod pretool_temporary_writes;
mod pretool_temporary_writes_windows;
mod pretool_windows_agent_root_listing;
mod pretool_windows_drive_cwd;
mod pretool_windows_home_writes;
mod pretool_word_count;
mod pretool_wrangler_reads;
mod pretool_zcode_dual_input;
mod pretool_zcode_dx_paths;
mod privileged_wrapper_floor;
mod reapproval_copy;
mod sed_workflow_boundaries;
mod sfrs_conformance;
mod workspace_write_boundaries;

#[test]
fn every_test_file_is_compiled() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let declared = include_str!("integration.rs");
    let cargo = std::fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(manifest.join("tests")).unwrap() {
        let path = entry.unwrap().path();
        let (Some(stem), Some("rs")) = (
            path.file_stem().and_then(|stem| stem.to_str()),
            path.extension().and_then(|extension| extension.to_str()),
        ) else {
            continue;
        };
        let target = format!("path = \"tests/{stem}.rs\"");
        if stem != "integration"
            && !declared.contains(&format!("\nmod {stem};\n"))
            && !cargo.contains(&target)
        {
            missing.push(stem.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "declare these test files in tests/integration.rs: {missing:?}"
    );
}
