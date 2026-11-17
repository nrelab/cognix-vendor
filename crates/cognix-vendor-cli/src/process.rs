//! Portable child-process construction.
//!
//! The parent Cognix repository's Clippy configuration forbids using
//! [`std::process::Command`] directly because spawning a child without
//! `CREATE_NO_WINDOW` briefly flashes a console window on Windows. This module
//! is the single place allowed to touch the standard-library type: it applies
//! the platform flags and exposes the small surface the CLI needs.
//!
//! Keeping the wrapper local (instead of depending on Cognix's `command` crate)
//! lets `cognix-vendor` remain a standalone workspace.

#![allow(clippy::disallowed_types)]

use std::{
    ffi::OsStr,
    io,
    path::Path,
    process::{Command as StdCommand, ExitStatus, Output},
};

/// A child process that is safe to launch from a console-free application.
#[derive(Debug)]
pub struct Command {
    inner: StdCommand,
}

impl Command {
    /// Create a command for `program`.
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        #[allow(unused_mut)]
        let mut inner = StdCommand::new(program);

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Equivalent to `windows_sys::Win32::System::Threading::CREATE_NO_WINDOW`.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            inner.creation_flags(CREATE_NO_WINDOW);
        }

        Self { inner }
    }

    /// Append arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    /// Append one argument.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.inner.arg(arg);
        self
    }

    /// Set the working directory.
    pub fn current_dir<P: AsRef<Path>>(&mut self, directory: P) -> &mut Self {
        self.inner.current_dir(directory);
        self
    }

    /// Set an environment variable for the child.
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        self.inner.env(key, value);
        self
    }

    /// Run the command to completion and capture stdout/stderr.
    pub fn output(&mut self) -> io::Result<Output> {
        self.inner.output()
    }

    /// Run the command to completion and return its exit status.
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        self.inner.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_without_a_shell() {
        // Use the current executable so the test does not depend on a shell.
        let mut command = Command::new(std::env::current_exe().expect("current executable"));
        command.arg("--help");
        let output = command.output().expect("run current executable");
        assert!(output.status.success());
    }
}
