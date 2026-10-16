use std::collections::BTreeSet;

use super::super::{code_lines, Language};
use super::{inline_loopback_ports, node_loopback_ports, program_ports};

/// A static file server an agent starts to look at the page it built.
const STATIC_SERVER: &str = "const http=require('node:http'),fs=require('node:fs'),path=require('node:path');const types={'.html':'text/html','.js':'text/javascript','.css':'text/css'};http.createServer((q,r)=>{const p=path.join(process.cwd(),q.url==='/'?'index.html':q.url);fs.readFile(p,(e,b)=>{r.writeHead(e?404:200,{'Content-Type':types[path.extname(p)]||'application/octet-stream'});r.end(e?'not found':b)})}).listen(4173,'127.0.0.1')";
/// The same server checking its own pages once it listens.
const SELF_CHECK: &str = "const http=require(\"node:http\"),fs=require(\"node:fs\");http.createServer((q,r)=>{fs.readFile(\".\"+q.url,(e,b)=>{r.writeHead(e?404:200);r.end(b)})}).listen(8765,\"127.0.0.1\",async()=>{for(const p of [\"/index.html\",\"/game.js\"]){const res=await fetch(\"http://127.0.0.1:8765\"+p);console.log(p,res.status)}process.exit(0)})";
/// A smoke test that starts the project's server and requests its root.
const SPAWNED_SERVER: &str = "import { spawn } from \"node:child_process\"; import assert from \"node:assert/strict\"; const child = spawn(process.execPath, [\"server.js\"], { stdio: \"inherit\" }); await new Promise((resolve) => setTimeout(resolve, 500)); const response = await fetch(\"http://127.0.0.1:3000/\"); assert.equal(response.status, 200); child.kill()";

fn ports(source: &str) -> Option<BTreeSet<u16>> {
    node_loopback_ports(&code_lines(Language::Node, source))
}

fn set(ports: &[u16]) -> Option<BTreeSet<u16>> {
    Some(ports.iter().copied().collect())
}

#[test]
fn loopback_servers_and_fetches_name_their_ports() {
    assert_eq!(ports(STATIC_SERVER), set(&[4173]));
    assert_eq!(ports(SELF_CHECK), set(&[8765]));
    assert_eq!(ports(SPAWNED_SERVER), set(&[3000]));
    assert_eq!(
        ports("const response = await fetch('http://localhost:5173/');\nconsole.log(response.status);\n"),
        set(&[5173])
    );
    assert_eq!(
        ports("import { createServer } from 'node:http';\ncreateServer((q, r) => r.end('ok')).listen(5173, 'localhost');\n"),
        set(&[5173])
    );
}

#[test]
fn other_network_use_keeps_the_review() {
    for source in [
        // Administrative loopback ports.
        "await fetch('http://127.0.0.1:2375/containers/json')",
        "await fetch('http://localhost:4781/approve')",
        "require('node:http').createServer().listen(9229, '127.0.0.1')",
        // Hosts other than loopback.
        "await fetch('https://example.com/')",
        "await fetch('http://example.com:80/')",
        "await fetch('http://127.0.0.2:8080/')",
        "await fetch('http://localhost.example.com:8080/')",
        "await fetch('http://127.0.0.1:3000/'); await fetch('https://example.com/')",
        "const http = require('http');\nhttp.createServer().listen(3000, '127.0.0.1');\nawait fetch('http://example.com/');\n",
        // Dynamic ports and hosts.
        "const http = require('http');\nhttp.createServer().listen(0, '127.0.0.1');\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT, '127.0.0.1');\n",
        "const http = require('http');\nhttp.createServer().listen(3000);\n",
        "const http = require('http');\nhttp.createServer().listen(3000, '0.0.0.0');\n",
        "const host = process.argv[2];\nawait fetch('http://' + host + ':3000/');\n",
        "const url = process.env.URL;\nawait fetch(url);\n",
        "await fetch(`http://127.0.0.1:${process.env.PORT}/`)",
        // Other network modules and HTTP clients.
        "const net = require('net');\nconst host = process.argv[2];\nnet.connect(80, host);\n",
        "import https from 'node:https';\nhttps.get('https://127.0.0.1:3000/');\n",
        "const http = require('http');\nhttp.get('http://127.0.0.1:3000/');\n",
        "const http = require('http');\nconst client = http;\nclient.get('http://127.0.0.1:3000/');\n",
        "const { request } = require('node:http');\nrequest('http://127.0.0.1:3000/').end();\n",
        "new WebSocket('ws://127.0.0.1:3000/')",
        // An import the binding forms do not name.
        "console.log(require('http').STATUS_CODES[200])",
        // A credential store alongside loopback traffic.
        "const fs = require('fs');\nconst key = fs.readFileSync(process.env.HOME + '/.ssh/id_ed25519');\nawait fetch('http://127.0.0.1:3000/', { method: 'POST', body: key });\n",
        // A string left open hides what follows it.
        "await fetch('http://127.0.0.1:3000/'); const s = 'open",
    ] {
        assert_eq!(ports(source), None, "{source}");
    }
}

#[test]
fn imported_modules_must_stay_off_the_network() {
    let server = "const http = require('http');\nhttp.createServer().listen(3000, '127.0.0.1');\n";
    assert_eq!(program_ports(&[server.into()]), set(&[3000]));
    assert_eq!(
        program_ports(&[
            server.into(),
            "module.exports = (rows) => rows.length;\n".into()
        ]),
        set(&[3000])
    );
    assert_eq!(
        program_ports(&[
            server.into(),
            "module.exports = () => fetch('https://example.com');\n".into()
        ]),
        None
    );
}

fn shell(text: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), text.into()]
}

#[test]
fn the_sandbox_reads_the_ports_from_the_command_it_runs() {
    assert_eq!(
        inline_loopback_ports(&shell(&format!(
            "node --test && node -e \"{STATIC_SERVER}\""
        ))),
        vec![4173]
    );
    assert_eq!(
        inline_loopback_ports(&shell(&format!(
            "node --input-type=module -e '{SPAWNED_SERVER}'"
        ))),
        vec![3000]
    );
    assert_eq!(
        inline_loopback_ports(&shell(
            "node -e \"fetch('http://127.0.0.1:3000/')\" && node -e \"fetch('http://localhost:5173/')\""
        )),
        vec![3000, 5173]
    );
    for text in [
        "node --test",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && node -e \"fetch('https://example.com/')\"",
        "node -e \"fetch('http://127.0.0.1:2375/')\"",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && python3 -c 'import socket'",
    ] {
        assert!(inline_loopback_ports(&shell(text)).is_empty(), "{text}");
    }
    let mut other = shell("node -e \"fetch('http://127.0.0.1:3000/')\"");
    other[0] = "/bin/bash".into();
    assert!(inline_loopback_ports(&other).is_empty());
}
