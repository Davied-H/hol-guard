use super::evaluate_pre_tool_with_context;
use crate::CommandModelRequestV1;

fn decide(command: &str) -> (String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let request = CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision = evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    (decision.minimum_action, decision.reason_code)
}

#[test]
fn read_only_loops_match_their_unrolled_form() {
    for (looped, unrolled) in [
        (
            "for f in a b; do echo \"--- $f\"; done",
            "echo \"--- a\"; echo \"--- b\"",
        ),
        (
            "for f in a b; do diff x/$f y/$f | head -8; done",
            "diff x/a y/a | head -8; diff x/b y/b | head -8",
        ),
        (
            "for f in src/a.ts src/b.ts; do diff -u \"old/$f\" \"new/$f\"; done",
            "diff -u \"old/src/a.ts\" \"new/src/a.ts\"; diff -u \"old/src/b.ts\" \"new/src/b.ts\"",
        ),
        (
            "for f in a b\ndo\n  echo ${f}\n  echo \"${f}\"\ndone",
            "echo a; echo a; echo b; echo b",
        ),
    ] {
        assert_eq!(decide(looped), decide(unrolled), "{looped}");
        assert_eq!(decide(looped).0, "allow", "{looped}");
    }
}

#[test]
fn unsafe_loop_bodies_keep_their_unrolled_verdict() {
    for (looped, unrolled) in [
        ("for f in a b; do rm $f; done", "rm a; rm b"),
        (
            "for f in a b; do echo hi > out/$f; done",
            "echo hi > out/a; echo hi > out/b",
        ),
        (
            "for f in a b; do cat ~/.ssh/$f; done",
            "cat ~/.ssh/a; cat ~/.ssh/b",
        ),
        (
            "for f in a b; do curl https://example.com/$f; done",
            "curl https://example.com/a; curl https://example.com/b",
        ),
        (
            "for f in a b; do echo $f; done > out.txt",
            "echo a > out.txt; echo b > out.txt",
        ),
        (
            "for f in a b; do git push origin $f; done",
            "git push origin a; git push origin b",
        ),
    ] {
        let looped_decision = decide(looped);
        assert_ne!(looped_decision.0, "allow", "{looped}");
        let unrolled_decision = decide(unrolled);
        assert_ne!(unrolled_decision.0, "allow", "{unrolled}");
        assert_eq!(
            looped_decision.0 == "block",
            unrolled_decision.0 == "block",
            "{looped}"
        );
    }
}

#[test]
fn unsupported_loops_fall_back_to_review() {
    for command in [
        "for f in $(ls); do echo $f; done",
        "for f in *.ts; do echo $f; done",
        "for f in a b; do $f; done",
        "for f in a b; do echo hi > $f; done",
        "for f in a b; do f=x; echo $f; done",
        "for f in a b; do echo $g; done",
        "for f in a b; do echo $(date); done",
        "for f in a b; do for g in c; do echo $g; done; done",
        "for f in a b; do if true; then echo $f; fi; done",
        "for f in a b; do echo $f &; done",
        "for f in \"a b\"; do echo $f; done",
        "for f in a b; do echo $f; done | sh",
        "for f in a b; do echo $f; done; rm x",
        "for 1f in a b; do echo $f; done",
        "for f in ~ b; do echo $f; done",
        // The body rebinds the loop variable or IFS, so `$f` would not be the header word.
        "for f in README.md; do read f; cat $f; done",
        "for f in README.md; do printf -v f %s secret; cat $f; done",
        "for f in README.md; do printf -vf %s secret; cat $f; done",
        "for f in README.md; do declare f=secret; cat $f; done",
        "for f in README.md; do unset f; cat $f; done",
        "for f in a,b; do export IFS=,; cat $f; done",
        "for f in README.md; do cat $f \u{1}; done",
    ] {
        assert_eq!(decide(command).0, "review", "{command}");
    }
    let many = (0..40)
        .map(|n| format!("w{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        decide(&format!("for f in {many}; do echo $f; done")).0,
        "review"
    );
}

#[test]
fn a_flag_named_like_the_loop_variable_is_not_a_rebinding() {
    assert_eq!(
        super::for_loop_unroll::unroll("for f in a b; do [ -f \"$f\" ] && wc -l \"$f\"; done")
            .as_deref(),
        Some("[ -f \"a\" ] && wc -l \"a\"; [ -f \"b\" ] && wc -l \"b\"")
    );
}
