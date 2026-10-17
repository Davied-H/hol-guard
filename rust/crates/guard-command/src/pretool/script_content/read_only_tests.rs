use super::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn script(name: &str, source: &str) -> (Scratch, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/read-only-script-unit")
        .join(format!(
            "run-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, source).unwrap();
    (Scratch(root.canonicalize().unwrap()), path)
}

#[test]
fn report_scripts_only_read() {
    let (_python, python) = script(
        "report.py",
        "from pathlib import Path\n\nfiles = list(Path(\"src\").iterdir())\nfirst = Path(\"src/one.ts\").read_text(encoding=\"utf-8\").splitlines()[0]\nprint(f\"report: {len(files)} files; first line: {first}\")\n",
    );
    assert!(read_only(Language::Python, &python));
    let (_node, node) = script(
        "report.mjs",
        "import { readdirSync, readFileSync } from 'node:fs';\n\nconst files = readdirSync('src');\nconst first = readFileSync('src/one.ts', 'utf8').split('\\n')[0];\nconsole.log(`report: ${files.length} files; first line: ${first}`);\n",
    );
    assert!(read_only(Language::Node, &node));
    let (_plain, plain) = script(
        "count.cjs",
        "const fs = require('fs');\nprocess.stdout.write(String(fs.readdirSync('.').length));\n",
    );
    assert!(read_only(Language::Node, &plain));
    let (_text, text) = script(
        "summary.py",
        "import sys\nname = sys.argv[0].replace('_', ' ')\nprint(name)\n",
    );
    assert!(read_only(Language::Python, &text));
}

#[test]
fn writes_launches_and_packages_keep_review() {
    for source in [
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        "import os\nos.remove('a')\n",
        "import shutil\n",
        "import subprocess\n",
        "import os.path, requests\n",
        "with open('out.txt', 'w') as f:\n    f.write('x')\n",
        "exec(open('x.py').read())\n",
        "import yaml\n",
        "from pathlib import Path\nPath('a').rename('b')\n",
    ] {
        let (_directory, path) = script("report.py", source);
        assert!(!read_only(Language::Python, &path), "{source}");
    }
    for source in [
        "import { writeFileSync } from 'node:fs';\nwriteFileSync('out.txt', 'x');\n",
        "import { execSync } from 'node:child_process';\n",
        "const lodash = require('lodash');\n",
        "const name = 'fs';\nrequire(name);\n",
        "await import('node:fs');\n",
        "import fs from 'fs';\nfs.rmSync('dist', { recursive: true });\n",
    ] {
        let (_directory, path) = script("report.mjs", source);
        assert!(!read_only(Language::Node, &path), "{source}");
    }
}

#[test]
fn network_and_credential_scripts_keep_review() {
    let (_python, python) = script(
        "report.py",
        "import urllib.request\nurllib.request.urlopen('https://example.com')\n",
    );
    assert!(!read_only(Language::Python, &python));
    let (_node, node) = script(
        "report.mjs",
        "import { readFileSync } from 'node:fs';\nreadFileSync(process.env.HOME + '/.aws/credentials');\n",
    );
    assert!(!read_only(Language::Node, &node));
}

#[test]
fn windows_route_takes_only_read_only_workspace_scripts() {
    let (scratch, _) = script("scripts/.keep", "");
    let workspace = scratch.0.to_str().unwrap().to_owned();
    std::fs::write(
        scratch.0.join("scripts/report.mjs"),
        "import { readdirSync } from 'node:fs';\nconsole.log(readdirSync('.').length);\n",
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("scripts/report.py"),
        "import os\nprint(len(os.listdir('.')))\n",
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("scripts/build.py"),
        "import shutil\nshutil.rmtree('dist')\n",
    )
    .unwrap();
    let reason = |command: &str| {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        crate::pretool::restricted_tests::windows_script_reason(
            &model,
            crate::pretool::PathContext {
                cwd: Some(&workspace),
                ..Default::default()
            },
        )
    };
    assert_eq!(
        reason("node scripts/report.mjs"),
        Some("native_node_eval_readonly_containment_required")
    );
    assert_eq!(
        reason("python scripts/report.py"),
        Some("native_python_eval_readonly_containment_required")
    );
    for command in [
        "python scripts/build.py",
        "python scripts/missing.py",
        "python ../report.py",
        "node scripts/report.mjs | head",
        "FOO=1 node scripts/report.mjs",
        "bash scripts/report.mjs",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
