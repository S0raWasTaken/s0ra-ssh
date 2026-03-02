use crate::{Res, fingerprint, print_err, sessions::SessionRegistry};
use libssh0::log;
use notify::{
    Event, EventKind, RecursiveMode::NonRecursive, Watcher, recommended_watcher,
};
use ssh_key::PublicKey;
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

pub type AuthorizedKeys = Arc<RwLock<Arc<[PublicKey]>>>;

pub fn watch_authorized_keys(
    config_dir: &Path,
    sessions: Arc<SessionRegistry>,
) -> Res<AuthorizedKeys> {
    let keys = Arc::new(RwLock::new(load_authorized_keys(config_dir)?.into()));
    let keys_clone = Arc::clone(&keys);

    let authorized_keys_path = config_dir.join("authorized_keys");
    let mut watcher =
        recommended_watcher(move |event: notify::Result<Event>| {
            watch(event, &authorized_keys_path, &sessions, &keys_clone);
        })?;

    watcher.watch(config_dir, NonRecursive)?;

    Box::leak(Box::new(watcher));

    Ok(keys)
}

fn watch(
    event: notify::Result<Event>,
    authorized_keys_path: &Path,
    sessions: &Arc<SessionRegistry>,
    keys: &AuthorizedKeys,
) {
    let Ok(event) = event else { return };

    if !event.paths.iter().any(|p| p == authorized_keys_path) {
        return;
    }

    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            match load_authorized_keys(authorized_keys_path) {
                Ok(new_keys) => {
                    let new_fingerprints =
                        new_keys.iter().map(fingerprint).collect();
                    sessions.kill_unlisted(&new_fingerprints);
                    *keys.write().unwrap() = new_keys.into();
                }
                Err(e) => print_err(&e),
            }
        }
        EventKind::Remove(_) => {
            sessions.kill_all();
            *keys.write().unwrap() = Arc::from([]);
            log!(e "authorized_keys deleted — all sessions killed, no new connections allowed");
        }
        _ => {}
    }
}

fn load_authorized_keys(authorized_keys_path: &Path) -> Res<Vec<PublicKey>> {
    Ok(ssh_key::AuthorizedKeys::read_file(authorized_keys_path)?
        .iter()
        .map(|e| e.public_key().clone())
        .collect::<Vec<_>>())
}
