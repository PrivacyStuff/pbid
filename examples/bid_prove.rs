//! Note prover. Reads one `pbid::job::Job` as JSON on stdin and writes the
//! `JobResult` on stdout. Errors go to stderr as one sentence with no note data.

use std::io::{Read, Write};

use pbid::job::{run, Job, JobError};

const BAD_JOB: &str = "The proof job is not valid JSON for this prover.";

fn main() {
    match prove_stdin() {
        Ok(line) => println!("{line}"),
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "{message}");
            std::process::exit(1);
        }
    }
}

fn prove_stdin() -> Result<String, &'static str> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).map_err(|_| BAD_JOB)?;
    let job: Job = serde_json::from_str(&raw).map_err(|_| BAD_JOB)?;
    let result = run(&job).map_err(JobError::as_str)?;
    serde_json::to_string(&result).map_err(|_| JobError::ProofFailed.as_str())
}
