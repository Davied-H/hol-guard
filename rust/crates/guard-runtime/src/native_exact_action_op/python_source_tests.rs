use super::scan;

fn modules(source: &str) -> Vec<String> {
    let mut found: Vec<String> = scan(source)
        .expect("readable")
        .imports
        .into_iter()
        .map(|import| {
            format!(
                "{}{}:{}",
                ".".repeat(import.level),
                import.module,
                import.names.join(",")
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn imports_are_read_in_every_statement_form() {
    let source = "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\"\"\"Report on the file system; eval nothing.\"\"\"\nfrom __future__ import annotations\nimport json, os.path as osp\nfrom pathlib import Path\nfrom .helpers import (\n    total,  # sum\n    mean as average,\n)\nimport re\n\ndef main():\n    try:\n        import csv\n    except ImportError as error:\n        raise SystemExit(1) from error\n    pattern = re.compile(r'\\d+')\n    rows = {'a': 1}\n    print(f\"{rows['a']:>4} {{literal}} {osp.sep}\", json.dumps(rows), Path, total, average, pattern, csv)\n\nif __name__ == '__main__':\n    main()\n";
    assert_eq!(
        modules(source),
        [
            ".helpers:total,mean",
            "__future__:annotations",
            "csv:",
            "json:",
            "os.path:",
            "pathlib:Path",
            "re:",
        ]
    );
    assert!(!scan(source).unwrap().writes);
}

#[test]
fn code_the_imports_do_not_name_is_refused() {
    for source in [
        "exec(open('x.py').read())\n",
        "eval('1')\n",
        "code = compile('1', 'x', 'eval')\n",
        "m = __import__('os')\n",
        "f = getattr(os, 'sys' + 'tem')\n",
        "warnings._setoption('ignore::pkg.Cls')\n",
        "unittest.mock.patch('pkg.get').start()\n",
        "os.system('ls')\n",
        "from os import system\n",
        "from os import *\n",
        "os.execv('/bin/sh', ['sh'])\n",
        "sys.path.insert(0, 'plugins')\n",
        "x = ().__class__.__bases__[0].__subclasses__()\n",
        "print('{0.__class__}'.format(1))\n",
        "print(f'{os.popen(\"id\").read()}')\n",
        "frame = sys._getframe(1)\n",
        "# -*- coding: rot13 -*-\nimport os\n",
        "x = 1 + \\\n  2\n",
        "\u{ff45}\u{ff58}\u{ff45}\u{ff43}('1')\n",
        "print(f'{\u{ff45}\u{ff58}\u{ff45}\u{ff43}(1)}')\n",
        "s = 'unterminated\n",
        "# note\rimport hidden\n",
        "x = f\"{d[\"k\"]}\"\nimport hidden\n",
        "x = f'{1 # comment\n}'\n",
        "x = t'{y}'\n",
        "import json\nimport\n",
        "import typing\nhints = typing.get_type_hints(Row)\n",
        "from typing import ForwardRef\n",
        "value = typing.evaluate_forward_ref(ref)\n",
        "hints = Row.__annotations__\n",
        "hints = Row.__annotate__(1)\n",
    ] {
        assert!(scan(source).is_none(), "{source}");
    }
}

#[test]
fn ordinary_text_is_readable() {
    for source in [
        "pattern = re.compile(r'[a-z]+')\nvalue = ast.literal_eval('[1]')\n",
        "print('caf\u{e9} \u{2014} done')\n# r\u{e9}sum\u{e9}: the system will evaluate this\n",
        "cursor.execute('select 1')\n",
        "raise ValueError('bad') from None\n",
        "def gen():\n    yield from range(3)\n",
        "print(f\"\u{2713} {count} files\")\r\n",
        "message = f'{name!r:>10}'\n",
        "parser.add_argument('--out', help='where to write')\ntext = text.replace('a', 'b')\n",
    ] {
        assert!(scan(source).is_some(), "{source}");
    }
}

#[test]
fn writes_are_seen_in_code_only() {
    assert!(
        scan("with open('out.json', 'w') as f:\n    f.write('{}')\n")
            .unwrap()
            .writes
    );
    assert!(scan("Path('x').write_text('y')\n").unwrap().writes);
    assert!(
        scan("import io, mmap\nhandle = io.FileIO('helpers.py', 'r+')\nview = mmap.mmap(handle.fileno(), 0)\nview[0:1] = b'#'\n")
            .unwrap()
            .writes
    );
    assert!(scan("os.ftruncate(fd, 0)\n").unwrap().writes);
    for source in [
        "open('x', 'w')\n",
        "open('x', mode='a')\n",
        "open('x', 'r+')\n",
        "open('x', mode)\n",
        "open('x', *args)\n",
        "open('x', **options)\n",
        "open('x', 'r', opener=make)\n",
        "open('x', 'r' 'w')\n",
        "open('x', r'w')\n",
        "Path('x').open('w')\n",
        "gzip.open('t', 'w')\n",
        "os.open('x', os.O_RDONLY)\n",
        "with open('x') as a, open('y', 'wb') as b:\n    pass\n",
        "open('x', ('w'))\n",
        "open('x'\n",
    ] {
        assert!(scan(source).is_none_or(|found| found.writes), "{source}");
    }
    for source in [
        "open('x')\n",
        "open('x', 'rb')\n",
        "open(path, encoding='utf-8', newline='')\n",
        "open(f'{name}.json', mode='rt')\n",
        "Path('x').open()\n",
        "Path('x').open('r', encoding='utf-8')\n",
        "if a == b:\n    open(p if a == b else q)\n",
    ] {
        assert!(!scan(source).unwrap().writes, "{source}");
    }
    assert!(
        !scan("# open( the door\nprint('shutil.rmtree(x)')\ntext = text.replace('a', 'b')\n")
            .unwrap()
            .writes
    );
}
