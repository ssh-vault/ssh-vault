pub mod create;
pub mod edit;
pub mod fingerprint;
pub mod view;

use secrecy::Secret;

#[derive(Debug)]
pub enum Action {
    Fingerprint {
        key: Option<String>,
        user: Option<String>,
    },
    Create {
        fingerprint: Option<String>,
        key: Option<String>,
        user: Option<String>,
        vault: Option<String>,
    },
    View {
        key: Option<String>,
        output: Option<String>,
        passphrase: Option<Secret<String>>,
        vault: Option<String>,
    },
    Edit {
        key: Option<String>,
        passphrase: Option<Secret<String>>,
        vault: String,
    },
    Help,
}
