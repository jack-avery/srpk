use arboard::Clipboard;

use crate::errors::{Result, SrpkError::Unknown};

pub fn set_clipboard(text: &str) -> Result<()> {
    let Ok(mut clipboard) = Clipboard::new() else {
        return Err(Unknown)
    };
    if clipboard.set_text(text).is_err() {
        return Err(Unknown)
    }
    Ok(())
}
