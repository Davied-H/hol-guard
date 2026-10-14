//! Line-numbered slices of a source file.
//!
//! Oh My Pi's `read` returns a selected range as `N:content` rows under a
//! `[path#hash]` header, with collapsed regions (`N-M:` rows), omission rows
//! (`…`) and notes. A secret elsewhere in the file is not in such a slice, so
//! when the whole file matches a secret rule the review scans only the lines
//! the slice covers. Every numbered row must equal that line of the current
//! file; stale or invented output keeps the whole-file decision.
//!
//! The scanner's rules each match within a line, except that a credential
//! name may sit a line or two above its value. The scanned range therefore
//! starts [`CONTEXT_LINES`] above the slice. A private key body has no marker
//! of its own, so a slice that overlaps a key block keeps the block.

/// Lines above a slice that are scanned with it.
pub(crate) const CONTEXT_LINES: usize = 3;

/// The first and last file line (1-based, inclusive) a slice covers, when
/// every numbered row matches the file.
pub(crate) fn covered_range(output: &str, file: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = file.lines().collect();
    let mut covered: Option<(usize, usize)> = None;
    let mut extend = |first: usize, last: usize| {
        covered = Some(match covered {
            Some((low, high)) => (low.min(first), high.max(last)),
            None => (first, last),
        });
    };
    for row in output.lines() {
        let Some((label, content)) = row.split_once(':') else {
            continue;
        };
        if let Some((first, last)) = label.split_once('-') {
            // A collapsed region: the host summarizes lines it does not show.
            let (Some(first), Some(last)) = (line_number(first), line_number(last)) else {
                continue;
            };
            if first > last || last > lines.len() {
                return None;
            }
            extend(first, last);
            continue;
        }
        let Some(number) = line_number(label) else {
            continue;
        };
        let line = lines.get(number.checked_sub(1)?)?;
        if !shows(content, line) {
            return None;
        }
        extend(number, number);
    }
    covered
}

/// Whether a private key block overlaps lines `first..=last`.
pub(crate) fn key_block_overlaps(file: &str, first: usize, last: usize) -> bool {
    let mut start = None;
    for (index, line) in file.lines().enumerate() {
        let number = index + 1;
        if start.is_none() && line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
            start = Some(number);
        }
        if let Some(begin) = start {
            if line.contains("-----END") {
                if begin <= last && number >= first {
                    return true;
                }
                start = None;
            }
        }
    }
    // An unterminated block runs to the end of the file.
    start.is_some_and(|begin| begin <= last)
}

/// File lines `first..=last` (1-based), joined.
pub(crate) fn lines(file: &str, first: usize, last: usize) -> String {
    file.lines()
        .skip(first.saturating_sub(1))
        .take(last + 1 - first.max(1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn line_number(label: &str) -> Option<usize> {
    if label.is_empty() || !label.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    label.parse().ok().filter(|number| *number > 0)
}

/// A row shows a line when it repeats it, or a prefix of it cut with `…`.
fn shows(content: &str, line: &str) -> bool {
    content == line
        || content
            .strip_suffix('…')
            .is_some_and(|prefix| line.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "one\ntwo\nthree\nfour\nfive\nsix";

    #[test]
    fn numbered_rows_must_repeat_the_file() {
        assert_eq!(
            covered_range("[f.sh#AB12]\n2:two\n3:three\n\n[2 more lines]", FILE),
            Some((2, 3))
        );
        assert_eq!(covered_range("4:fo…\n5-6:  { … }", FILE), Some((4, 6)));
        assert_eq!(covered_range("1:one\n…\n6:six", FILE), Some((1, 6)));
        for output in [
            "2:tw0",
            "2:two\n3:four",
            "7:seven",
            "0:one",
            "1:on…e",
            "4-9: …",
        ] {
            assert_eq!(covered_range(output, FILE), None, "{output:?}");
        }
        assert_eq!(covered_range("[f.sh#AB12]\nno rows", FILE), None);
    }

    #[test]
    fn key_blocks_overlapping_a_slice_are_found() {
        let file = "a\n-----BEGIN PRIVATE KEY-----\nbody\nbody\n-----END PRIVATE KEY-----\nb\nc";
        assert!(key_block_overlaps(file, 3, 4));
        assert!(key_block_overlaps(file, 5, 7));
        assert!(!key_block_overlaps(file, 6, 7));
        assert!(!key_block_overlaps(file, 1, 1));
        let open = "a\nb\n-----BEGIN RSA PRIVATE KEY-----\nbody\nbody";
        assert!(key_block_overlaps(open, 5, 5));
        assert!(!key_block_overlaps(open, 1, 2));
    }

    #[test]
    fn lines_are_taken_by_number() {
        assert_eq!(lines(FILE, 2, 3), "two\nthree");
        assert_eq!(lines(FILE, 1, 1), "one");
        assert_eq!(lines(FILE, 5, 9), "five\nsix");
    }
}
