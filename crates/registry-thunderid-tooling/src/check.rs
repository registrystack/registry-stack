//! The offline check of the platform files this crate reads (CFG-CHECK-1):
//! a task connection file (`PlatformTaskConnection`) and a development
//! session state file (`PlatformThunderidSession`), each identified by its
//! envelope.
//!
//! A check reads one file through the shared reader and applies every rule
//! reading it for use would apply that needs no network. It resolves no
//! secret reference and judges no file mode: those happen only when a
//! grant is acquired.

use std::io::Read;
use std::path::Path;

use registry_platform_yaml::{Diagnostic, Expect, Reader, Report, Source, MAXIMUM_DOCUMENT_BYTES};

use crate::container::{StateFile, SESSION_FORMAT, SESSION_KIND};
use crate::task_connection::{self, TaskConnection};

/// The outcome of checking one file.
pub struct FileCheck {
    /// Every finding, with one file checked.
    pub report: Report,
    /// The file could not be read at all, so nothing was checked.
    pub unreadable: bool,
}

/// Check the file at `path`, naming it as written in every diagnostic.
pub fn check_file(path: &Path) -> FileCheck {
    let file = path.display().to_string();
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path).and_then(|opened| {
        opened
            .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
    });
    if read.is_err() {
        let mut diagnostic = Diagnostic::error(
            "platform.check.unreadable",
            "",
            "the file cannot be read",
            "Pass the path of an existing, readable task connection or session state file.",
        );
        diagnostic.source = Some(Source {
            file,
            line: None,
            column: None,
        });
        let mut report = Report::new(vec![diagnostic]);
        report.set_files_checked(1);
        return FileCheck {
            report,
            unreadable: true,
        };
    }
    let mut report = check_bytes(&file, &bytes);
    report.set_files_checked(1);
    FileCheck {
        report,
        unreadable: false,
    }
}

fn check_bytes(file: &str, bytes: &[u8]) -> Report {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let formats = [task_connection::FORMAT, SESSION_FORMAT];
    let document = match Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::new(&formats))
    {
        Ok(document) => document,
        Err(report) => return report,
    };
    let mut report = document.warnings();
    if document.envelope().kind == SESSION_KIND {
        if let Err(refused) = document.decode::<StateFile>() {
            report.extend(refused);
        }
        return report;
    }
    match document.decode::<TaskConnection>() {
        Ok(connection) => {
            for diagnostic in task_connection::check(&document, &connection) {
                report.push(diagnostic);
            }
        }
        Err(refused) => report.extend(refused),
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLATFORM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/platform");

    fn codes(report: &Report) -> Vec<(String, String)> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    fn scratch() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "platform-check-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn checked(name: &str, text: &str) -> FileCheck {
        let root = scratch();
        let path = root.join(name);
        std::fs::write(&path, text).unwrap();
        let checked = check_file(&path);
        std::fs::remove_dir_all(&root).unwrap();
        checked
    }

    #[test]
    fn the_committed_examples_pass() {
        for example in ["task-connection.yaml", "thunderid/session.json"] {
            let checked = check_file(&Path::new(PLATFORM).join("examples").join(example));
            assert!(!checked.unreadable, "{example}");
            assert!(checked.report.is_empty(), "{example}: {}", checked.report);
            assert_eq!(checked.report.files_checked(), Some(1), "{example}");
        }
    }

    #[test]
    fn a_task_connection_is_checked_beyond_its_types() {
        let example =
            std::fs::read_to_string(Path::new(PLATFORM).join("examples/task-connection.yaml"))
                .unwrap();
        let text = example.replace("http://127.0.0.1:8090", "http://casework.example");
        let checked = checked("connection.yaml", &text);
        assert!(!checked.unreadable);
        assert_eq!(
            codes(&checked.report),
            [(
                "platform.task-connection.invalid-endpoint".to_owned(),
                "/caseworkUrl".to_owned()
            )]
        );
        assert_eq!(checked.report.files_checked(), Some(1));
    }

    #[test]
    fn a_session_state_file_is_checked_by_its_envelope() {
        let checked = checked(
            "session.json",
            &format!(
                "{{\"apiVersion\":\"{}\",\"kind\":\"{SESSION_KIND}\",\"setupComplete\":\"yes\"}}",
                crate::container::SESSION_API_VERSION
            ),
        );
        assert_eq!(
            codes(&checked.report),
            [(
                "config.expected-boolean".to_owned(),
                "/setupComplete".to_owned()
            )]
        );
    }

    #[test]
    fn another_format_is_refused_by_its_envelope() {
        let checked = checked(
            "other.yaml",
            "apiVersion: id.registrystack.org/formats/discovery/origins/v1alpha1\nkind: DiscoveryOrigins\n",
        );
        assert!(!checked.unreadable);
        assert_eq!(checked.report.error_count(), 1, "{}", checked.report);
    }

    #[test]
    fn a_missing_file_is_unreadable() {
        let root = scratch();
        let checked = check_file(&root.join("absent.yaml"));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(checked.unreadable);
        assert_eq!(
            codes(&checked.report),
            [("platform.check.unreadable".to_owned(), String::new())]
        );
        assert_eq!(checked.report.files_checked(), Some(1));
    }

    #[test]
    fn cfg_sec_2_an_expression_is_refused_without_resolving_it() {
        let example =
            std::fs::read_to_string(Path::new(PLATFORM).join("examples/task-connection.yaml"))
                .unwrap();
        let text = example.replace("urn:registry:casework", "${BOOTSTRAP_RESOURCE}");
        let checked = checked("connection.yaml", &text);
        assert_eq!(
            codes(&checked.report),
            [(
                "config.substitution-not-allowed".to_owned(),
                "/bootstrapResource".to_owned()
            )]
        );
        assert!(!checked.report.render_human().contains("BOOTSTRAP_RESOURCE"));
    }
}
