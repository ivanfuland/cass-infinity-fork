use clap::{Parser, error::ErrorKind};
use coding_agent_search::{Cli, Commands, ModelsCommand};

fn parse(args: &[&str]) -> Result<Cli, String> {
    Cli::try_parse_from(args).map_err(|err| format!("parse cass CLI for {args:?}: {err}"))
}

fn run_on_large_stack<F>(f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name("cli-model-lifecycle-contract".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .map_err(|err| format!("spawn large-stack CLI parser test: {err}"))?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => Err("large-stack CLI parser test panicked".to_string()),
    }
}

#[test]
fn models_install_from_file_keeps_acquisition_data_dir_scoped() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "install",
            "--model",
            "all-minilm-l6-v2",
            "--from-file",
            "/seeded/models/all-minilm-l6-v2",
            "--data-dir",
            "/cass/models",
            "--yes",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Install {
                model,
                mirror: None,
                from_file: Some(from_file),
                yes: true,
                data_dir: Some(data_dir),
            })) if model.as_deref() == Some("all-minilm-l6-v2")
                && from_file.display().to_string() == "/seeded/models/all-minilm-l6-v2"
                && data_dir.display().to_string() == "/cass/models" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected local model acquisition controls to parse: {other:?}"
            )),
        }
    })
}

#[test]
fn models_install_from_mirror_keeps_acquisition_data_dir_scoped() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "install",
            "--model",
            "all-minilm-l6-v2",
            "--mirror",
            "https://mirror.example/models",
            "--data-dir",
            "/cass/models",
            "--yes",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Install {
                model,
                mirror: Some(mirror),
                from_file: None,
                yes: true,
                data_dir: Some(data_dir),
            })) if model.as_deref() == Some("all-minilm-l6-v2")
                && mirror == "https://mirror.example/models"
                && data_dir.display().to_string() == "/cass/models" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected mirror model acquisition controls to parse: {other:?}"
            )),
        }
    })
}

#[test]
fn models_install_rejects_ambiguous_mirror_and_from_file_sources() -> Result<(), String> {
    run_on_large_stack(|| {
        let result = Cli::try_parse_from([
            "cass",
            "models",
            "install",
            "--mirror",
            "https://mirror.example/models",
            "--from-file",
            "/seeded/models/all-minilm-l6-v2",
            "--data-dir",
            "/cass/models",
            "--yes",
        ]);

        match result {
            Err(err) if err.kind() == ErrorKind::ArgumentConflict => Ok(()),
            Err(err) => Err(format!(
                "expected mirror/from-file acquisition conflict, got {:?}: {err}",
                err.kind()
            )),
            Ok(cli) => Err(format!(
                "expected mirror/from-file acquisition conflict, parsed: {cli:?}"
            )),
        }
    })
}

#[test]
fn retired_install_does_not_select_a_default_model() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&["cass", "models", "install", "--data-dir", "/cass/models"])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Install {
                model,
                mirror: None,
                from_file: None,
                yes: false,
                data_dir: Some(data_dir),
            })) if model.is_none()
                && data_dir.display().to_string() == "/cass/models" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected default model acquisition controls to stay confirmation-gated: {other:?}"
            )),
        }
    })
}

#[test]
fn models_verify_repair_controls_remain_data_dir_scoped() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "verify",
            "--repair",
            "--data-dir",
            "/cass/models",
            "--json",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Verify {
                repair: true,
                data_dir: Some(data_dir),
                json: true,
            })) if data_dir.display().to_string() == "/cass/models" => Ok(()),
            other => Err(format!(
                "expected data-dir scoped model verify repair controls: {other:?}"
            )),
        }
    })
}

#[test]
fn models_verify_defaults_to_inspection_without_repair() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "verify",
            "--data-dir",
            "/cass/models",
            "--json",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Verify {
                repair: false,
                data_dir: Some(data_dir),
                json: true,
            })) if data_dir.display().to_string() == "/cass/models" => Ok(()),
            other => Err(format!(
                "expected model verification to default to inspect-only mode: {other:?}"
            )),
        }
    })
}

#[test]
fn models_verify_json_is_a_migration_refusal_and_creates_no_model_dir() {
    use assert_cmd::cargo::cargo_bin;

    // Semantic mapping (model-API migration): this test used to assert that
    // `models verify --json` emitted a fail-open local lifecycle payload
    // (`status=not_acquired`, `all_valid=false`, `cache_lifecycle`, `model_dir`)
    // without creating the model directory. Local weight verification was
    // retired, so the surviving contract is stricter: the command refuses with a
    // migration error (exit 2) and still must not create a model directory.
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let output = std::process::Command::new(cargo_bin("cass"))
        .args(["models", "verify", "--json", "--data-dir"])
        .arg(&data_dir)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join(".local/share"))
        .env("XDG_CONFIG_HOME", tmp.path().join(".config"))
        .output()
        .expect("run cass models verify --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "models verify must be a migration refusal; stdout: {stdout}\nstderr: {stderr}"
    );

    let model_dir = data_dir.join("models");
    assert!(
        !model_dir.exists(),
        "a retired verify must not create a model directory; got {}",
        model_dir.display()
    );
}

#[test]
fn models_remove_requires_explicit_model_and_yes_controls() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "remove",
            "--model",
            "all-minilm-l6-v2",
            "--data-dir",
            "/cass/models",
            "--yes",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Remove {
                model,
                yes: true,
                data_dir: Some(data_dir),
            })) if model.as_deref() == Some("all-minilm-l6-v2")
                && data_dir.display().to_string() == "/cass/models" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected explicit model removal controls to parse: {other:?}"
            )),
        }
    })
}

#[test]
fn retired_remove_does_not_select_a_default_model() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&["cass", "models", "remove", "--data-dir", "/cass/models"])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Remove {
                model,
                yes: false,
                data_dir: Some(data_dir),
            })) if model.is_none()
                && data_dir.display().to_string() == "/cass/models" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected model removal to default to interactive reclamation: {other:?}"
            )),
        }
    })
}

#[test]
fn models_check_update_reports_against_scoped_data_dir() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "check-update",
            "--data-dir",
            "/cass/models",
            "--json",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::CheckUpdate {
                data_dir: Some(data_dir),
                json: true,
            })) if data_dir.display().to_string() == "/cass/models" => Ok(()),
            other => Err(format!(
                "expected scoped model update check controls to parse: {other:?}"
            )),
        }
    })
}

#[test]
fn models_backfill_keeps_semantic_work_data_dir_and_db_scoped() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&[
            "cass",
            "models",
            "backfill",
            "--tier",
            "quality",
            "--embedder",
            "fastembed",
            "--batch-conversations",
            "17",
            "--scheduled",
            "--data-dir",
            "/cass/data",
            "--db",
            "/cass/data/agent_search.db",
            "--json",
        ])?;

        match cli.command {
            Some(Commands::Models(ModelsCommand::Backfill {
                tier,
                embedder: Some(embedder),
                embedding_profile: None,
                no_model_fallback: false,
                batch_conversations: 17,
                scheduled: true,
                data_dir: Some(data_dir),
                db: Some(db),
                json: true,
            })) if tier.as_deref() == Some("quality")
                && embedder == "fastembed"
                && data_dir.display().to_string() == "/cass/data"
                && db.display().to_string() == "/cass/data/agent_search.db" =>
            {
                Ok(())
            }
            other => Err(format!(
                "expected scoped model backfill controls to parse: {other:?}"
            )),
        }
    })
}

// ========================================================================
// Bead coding_agent_session_search-7hot1 (child of ibuuh.10, scenario G:
// semantic model acquisition — air-gap entry point, error-envelope E2E).
//
// AGENTS.md's Search Asset Contract promises: "Semantic model acquisition
// is opt-in... Air-gapped installs use `--from-file <dir>`." The existing
// arg-parse contract tests above pin the CLI shape, but no test pins the
// RUNTIME validation error surface emitted by src/lib.rs::run_models_install
// at line ~26760. Three distinct validation errors can fire there —
// not-a-directory, missing required file, and mirror/from-file conflict —
// and all three are silently untested at the user-visible stderr boundary.
//
// A regression that changed err.kind from "model" to something else,
// dropped the hint pointing operators at the expected file set, or
// silently accepted a partial file set would not be caught by the
// arg-parse tests above. This gap matters especially for agents
// running air-gapped installs: they consume the JSON error envelope
// to decide what to do next.
//
// Contract pinned here, for the two cases that don't need the real
// ~90MB MiniLM model (which this test fixture deliberately avoids):
//   1. --from-file <nonexistent-path>
//      - exit 21, err.kind == "model", err.code == 21,
//        err.retryable == false, hint names "directory" + expected
//        model file examples.
//   2. --from-file <empty-dir>
//      - exit 21, err.kind == "model", err.code == 21,
//        err.retryable == false, hint enumerates the required file set
//        (model.onnx, tokenizer.json, config.json, ...).
// ========================================================================

// Semantic mapping (model-API migration):
// `models_install_from_file_nonexistent_path_emits_model_error_envelope` and
// `models_install_from_file_empty_dir_emits_required_file_error` asserted the
// retired local-install `--from-file` validation (exit 21, err.kind "model",
// "is not a directory" / "Required file ... not found"). Local installation is
// retired, so the two collapse into one assertion: install refuses with a
// migration error before it ever reads a source directory, whichever source
// path is given.
#[test]
fn models_install_from_file_refuses_with_a_migration_error() {
    use assert_cmd::cargo::cargo_bin;

    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("cass-data");
    let model_src = tmp.path().join("model-source");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    std::fs::create_dir_all(&model_src).expect("create empty model source dir");
    let nonexistent = tmp.path().join("definitely-not-there");

    for source in [&nonexistent, &model_src] {
        let output = std::process::Command::new(cargo_bin("cass"))
            .args(["models", "install", "--from-file"])
            .arg(source)
            .args(["--yes", "--robot-format", "json", "--data-dir"])
            .arg(&data_dir)
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("CASS_IGNORE_SOURCES_CONFIG", "1")
            .env("HOME", tmp.path())
            .env("XDG_DATA_HOME", tmp.path().join(".local/share"))
            .env("XDG_CONFIG_HOME", tmp.path().join(".config"))
            .output()
            .expect("run cass models install");

        let exit = output.status.code().expect("exit code present");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            exit, 2,
            "models install must refuse with a migration error (exit 2) whatever the source path; \
             source: {source:?}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

// `models_install_from_file_empty_dir_emits_required_file_error` was removed
// with the local-install surface; its empty-source-directory case is folded into
// `models_install_from_file_refuses_with_a_migration_error` above, which runs
// both an empty and a nonexistent source directory.

// ========================================================================
// API01C: the API-only model commands `models list` / `models check` and the
// global `--api-config` selector.
//
// These pin the *arg-parse* contract only. The runtime behaviour (a real
// subprocess against a loopback HTTP service) lives in
// `tests/api_model_commands.rs`. Adding the two variants must not disturb
// any contract asserted above: every pre-existing test in this file stays
// byte-for-byte and must keep passing.
// ========================================================================

#[test]
fn models_list_parses_with_and_without_json() -> Result<(), String> {
    run_on_large_stack(|| {
        let plain = parse(&["cass", "models", "list"])?;
        match plain.command {
            Some(Commands::Models(ModelsCommand::List { json: false })) => {}
            other => {
                return Err(format!(
                    "expected `models list` to default to human output: {other:?}"
                ));
            }
        }

        let json = parse(&["cass", "models", "list", "--json"])?;
        match json.command {
            Some(Commands::Models(ModelsCommand::List { json: true })) => Ok(()),
            other => Err(format!("expected `models list --json` to set json: {other:?}")),
        }
    })
}

#[test]
fn models_list_accepts_the_robot_alias() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&["cass", "models", "list", "--robot"])?;
        match cli.command {
            Some(Commands::Models(ModelsCommand::List { json: true })) => Ok(()),
            other => Err(format!("expected `--robot` to alias `--json`: {other:?}")),
        }
    })
}

#[test]
fn models_check_parses_the_required_profile() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&["cass", "models", "check", "--profile", "local-embed"])?;
        match cli.command {
            Some(Commands::Models(ModelsCommand::Check {
                profile,
                json: false,
            })) if profile == "local-embed" => {}
            other => {
                return Err(format!(
                    "expected `models check --profile <ID>` to parse: {other:?}"
                ));
            }
        }

        let json = parse(&[
            "cass",
            "models",
            "check",
            "--profile",
            "local-rank",
            "--json",
        ])?;
        match json.command {
            Some(Commands::Models(ModelsCommand::Check {
                profile,
                json: true,
            })) if profile == "local-rank" => Ok(()),
            other => Err(format!(
                "expected `models check --profile <ID> --json` to parse: {other:?}"
            )),
        }
    })
}

#[test]
fn models_check_without_a_profile_is_a_usage_error() -> Result<(), String> {
    run_on_large_stack(|| {
        let err = parse(&["cass", "models", "check"])
            .expect_err("`--profile` is required, so this must be refused");
        assert!(
            err.contains("profile"),
            "the refusal must name the missing profile argument; got: {err}"
        );
        Ok(())
    })
}

#[test]
fn api_config_is_global_and_usable_before_or_after_the_subcommand() -> Result<(), String> {
    run_on_large_stack(|| {
        let before = parse(&[
            "cass",
            "--api-config",
            "/etc/cass/models.toml",
            "models",
            "list",
        ])?;
        match before.api_config {
            Some(path) if path.display().to_string() == "/etc/cass/models.toml" => {}
            other => return Err(format!("expected the leading --api-config: {other:?}")),
        }
        assert!(matches!(
            before.command,
            Some(Commands::Models(ModelsCommand::List { .. }))
        ));

        let after = parse(&[
            "cass",
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            "/etc/cass/other.toml",
        ])?;
        match after.api_config {
            Some(path) if path.display().to_string() == "/etc/cass/other.toml" => {}
            other => return Err(format!("expected the trailing --api-config: {other:?}")),
        }
        assert!(matches!(
            after.command,
            Some(Commands::Models(ModelsCommand::Check { .. }))
        ));

        let inline = parse(&["cass", "models", "list", "--api-config=/etc/cass/inline.toml"])?;
        match inline.api_config {
            Some(path) if path.display().to_string() == "/etc/cass/inline.toml" => Ok(()),
            other => Err(format!(
                "expected the inline --api-config=<PATH> form: {other:?}"
            )),
        }
    })
}

#[test]
fn api_config_is_absent_by_default() -> Result<(), String> {
    run_on_large_stack(|| {
        let cli = parse(&["cass", "models", "status", "--json"])?;
        if cli.api_config.is_some() {
            return Err(format!(
                "expected no api_config unless the operator names one: {:?}",
                cli.api_config
            ));
        }
        Ok(())
    })
}
