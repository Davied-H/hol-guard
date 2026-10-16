use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::context::{Ctx, Engines, LocalExecution};
use super::super::launch::launch_identity;
use super::python_script;

struct Fixed;

impl Engines for Fixed {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"executable": executable, "args": args})
    }

    fn launch_reusable(&self, _identity: &Value) -> bool {
        true
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        None
    }
}

/// A project below the target directory: macOS `$TMPDIR` resolves under
/// `/private/var`, which the sensitive-path screen rejects.
struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/python-script-tests")
            .join(format!(
                "p-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn cwd(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bind(project: &Project, args: &[&str], env: &[(&str, &str)]) -> Result<Value, &'static str> {
    let env: BTreeMap<String, String> = env
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let ctx = Ctx {
        home: None,
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    python_script(&args, project.cwd(), &ctx)
}

fn launch(project: &Project, command: &str) -> Result<Value, &'static str> {
    let env = BTreeMap::new();
    let ctx = Ctx {
        home: None,
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    launch_identity(command, project.cwd(), &ctx)
}

fn report_project() -> Project {
    let project = Project::new();
    project.write(
        "scripts/report.py",
        "#!/usr/bin/env python3\n\"\"\"Summarize rows; the system never evaluates input.\"\"\"\nfrom __future__ import annotations\n\nimport json, os.path\nfrom pathlib import Path\n\nimport helpers\nfrom lib import fmt\nfrom lib.totals import total\n\n\ndef main() -> None:\n    rows = json.loads(Path(os.path.join('data', 'rows.json')).read_text())\n    print(f\"{fmt.label(rows['name'])}: {total(rows['values'])}\", helpers.VERSION)\n\n\nif __name__ == '__main__':\n    main()\n",
    );
    project.write("scripts/helpers.py", "VERSION = '1.0'\n");
    project.write("scripts/lib/__init__.py", "");
    project.write(
        "scripts/lib/fmt.py",
        "import textwrap\n\n\ndef label(name):\n    return textwrap.shorten(name, 20)\n",
    );
    project.write(
        "scripts/lib/totals.py",
        "from .fmt import label\n\n\ndef total(values):\n    return sum(values)\n",
    );
    project
}

fn module_paths(bound: &Value) -> Vec<String> {
    bound["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|module| module["path"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_script_binds_its_local_modules_by_content_and_standard_modules_by_name() {
    let project = report_project();
    let bound = bind(&project, &["scripts/report.py"], &[]).unwrap();
    let root = project.cwd();
    assert_eq!(bound["script"], format!("{root}/scripts/report.py"));
    assert_eq!(
        module_paths(&bound),
        [
            format!("{root}/scripts/helpers.py"),
            format!("{root}/scripts/lib/__init__.py"),
            format!("{root}/scripts/lib/fmt.py"),
            format!("{root}/scripts/lib/totals.py"),
            format!("{root}/scripts/report.py"),
        ]
    );
    assert_eq!(
        bound["standard"],
        json!(["__future__", "json", "os", "pathlib", "textwrap"])
    );
    assert_eq!(
        bind(&project, &["-u", "-B", "scripts/report.py"], &[]).unwrap()["modules"],
        bound["modules"]
    );

    project.write("scripts/helpers.py", "VERSION = '2.0'\n");
    let edited = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_ne!(edited["modules"], bound["modules"]);
}

#[test]
fn cached_bytecode_beside_a_local_module_is_bound() {
    let project = report_project();
    let before = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(before["bytecode"], json!([]));
    project.write("scripts/__pycache__/helpers.cpython-312.pyc", "one");
    let cached = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(cached["bytecode"].as_array().unwrap().len(), 1);
    project.write("scripts/__pycache__/helpers.cpython-312.pyc", "two");
    let replaced = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_ne!(replaced["bytecode"], cached["bytecode"]);
}

#[test]
fn a_module_beside_the_script_shadows_the_standard_one() {
    let project = Project::new();
    project.write("tool.py", "import json\nprint(json.dumps(1))\n");
    project.write("json.py", "def dumps(value):\n    return str(value)\n");
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert_eq!(module_paths(&bound).len(), 2);
    assert_eq!(bound["standard"], json!([]));
    // Without the script's directory on the module path, the standard one loads.
    let isolated = bind(&project, &["-I", "tool.py"], &[]).unwrap();
    assert_eq!(module_paths(&isolated).len(), 1);
    assert_eq!(isolated["standard"], json!(["json"]));
}

#[test]
fn a_single_file_script_that_writes_files_is_bound() {
    let project = Project::new();
    project.write(
        "gen.py",
        "import json\nfrom pathlib import Path\n\nPath('out').mkdir(exist_ok=True)\nwith open('out/data.json', 'w') as handle:\n    json.dump({'ok': True}, handle)\n",
    );
    assert!(bind(&project, &["gen.py"], &[]).is_ok());
}

#[test]
fn code_the_graph_cannot_bind_keeps_the_launch_once_only() {
    for (files, args) in [
        (vec![("t.py", "import requests\n")], vec!["t.py"]),
        (vec![("t.py", "import subprocess\n")], vec!["t.py"]),
        (
            vec![("t.py", "from importlib import import_module\n")],
            vec!["t.py"],
        ),
        (vec![("t.py", "import os\nos.system('ls')\n")], vec!["t.py"]),
        (vec![("t.py", "exec(input())\n")], vec!["t.py"]),
        (vec![("t.py", "from . import x\n")], vec!["t.py"]),
        (vec![("t.py", "import helpers\n")], vec!["-I", "t.py"]),
        (
            vec![("t.py", "import helpers\n"), ("helpers.py", "eval('1')\n")],
            vec!["t.py"],
        ),
        (
            vec![
                ("t.py", "import helpers\n"),
                ("helpers.py", "X = 1\n"),
                ("helpers.cpython-312-darwin.so", ""),
            ],
            vec!["t.py"],
        ),
        (
            vec![("t.py", "import json\n"), ("json.pyc", "")],
            vec!["t.py"],
        ),
        (
            vec![
                (
                    "t.py",
                    "import helpers\nopen('helpers.py', 'w').write('X = 2')\n",
                ),
                ("helpers.py", "X = 1\n"),
            ],
            vec!["t.py"],
        ),
        (
            vec![("t.py", "import pkg\n"), ("pkg/mod.py", "")],
            vec!["t.py"],
        ),
        (
            vec![
                ("t.py", "import pkg.sub\n"),
                ("pkg/__init__.py", "from .. import t\n"),
                ("pkg/sub.py", ""),
            ],
            vec!["t.py"],
        ),
        (vec![("t.py", "print(1)\n")], vec!["-c", "print(1)"]),
        (vec![("t.py", "print(1)\n")], vec!["-m", "t"]),
        (vec![("t.py", "print(1)\n")], vec!["-W", "error", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-X", "dev", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-i", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["--", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-"]),
        (vec![("t.py", "print(1)\n")], vec![]),
        (vec![("t.py", "print(1)\n")], vec!["missing.py"]),
        (vec![("t.txt", "print(1)\n")], vec!["t.txt"]),
    ] {
        let project = Project::new();
        for (path, text) in &files {
            project.write(path, text);
        }
        assert_eq!(
            bind(&project, &args, &[]),
            Err("mutable_launcher"),
            "{files:?} {args:?}"
        );
    }
    let project = Project::new();
    project.write("t.py", "print(1)\n");
    for name in [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONWARNINGS",
        "PYTHONPYCACHEPREFIX",
        "pythonpath",
    ] {
        assert_eq!(
            bind(&project, &["t.py"], &[(name, "x")]),
            Err("mutable_launcher"),
            "{name}"
        );
    }
    assert!(bind(&project, &["t.py"], &[("PYTHONPATH", "")]).is_ok());
    assert!(bind(&project, &["-OO", "-uB", "t.py", "--flag"], &[]).is_ok());
}

#[test]
fn only_a_single_python_launch_gets_a_script_identity() {
    let project = report_project();
    let launched = launch(&project, "python3 scripts/report.py").unwrap();
    assert_eq!(launched["kind"], "python-script");
    assert!(launch(&project, "python scripts/report.py").is_ok());
    assert!(launch(&project, "python3.12 scripts/report.py").is_ok());
    assert_eq!(launch(&project, "python3 -c 1"), Err("mutable_launcher"));
    assert_eq!(
        launch(&project, "cd scripts && python3 report.py"),
        Err("compound_command")
    );
}
