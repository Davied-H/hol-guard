//! Narrow public surface for resident access to the existing model helpers.
pub use crate::command_segment_parsing::shell_tokens_without_redirects;
pub use crate::command_structure::{
    build_command_security_identity, extract_command_redirects, CommandRedirect, EmbeddedCommand,
    IdentitySegment,
};
pub use crate::command_tokens::{
    after_sudo_options, executable_name, leading_environment, shell_tokens, windows_shell_tokens,
};
pub use crate::env_wrapper::parse_env_wrapper;
pub use crate::shell_structure::ShellHeredoc;

pub fn decode_command_gzip_chunks(chunks: &[String]) -> Result<String, &'static str> {
    use base64::Engine;
    use std::io::Read;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(chunks.concat())
        .map_err(|_| "native_rich_command_model_invalid_args")?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "native_rich_command_model_invalid_args")?;
    if text.len() > 8 * 1024 * 1024 {
        return Err("native_rich_command_model_bounds");
    }
    Ok(text)
}
