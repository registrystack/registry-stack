// SPDX-License-Identifier: Apache-2.0
//! Keep private fixture evidence when a retained database proof fails.
use std::path::Path;

pub struct FixtureDirectory(Option<tempfile::TempDir>);
impl FixtureDirectory {
    pub fn new(root: tempfile::TempDir) -> Self {
        Self(Some(root))
    }
    pub fn path(&self) -> &Path {
        self.0.as_ref().expect("fixture directory").path()
    }
}
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(root) = self.0.take() {
                eprintln!(
                    "retained private fixture evidence: {}",
                    root.keep().display()
                );
            }
        }
    }
}
