use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Modbus error: {0}")]
    Modbus(String),

    #[error("SSH error: {0}")]
    Ssh(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Security: {0}")]
    Security(String),
}

pub type AdapterResult<T> = Result<T, AdapterError>;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("device not found: {0}")]
    NotFound(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session already exists: {0}")]
    SessionExists(String),

    #[error("ssh connection failed: {0}")]
    Connection(String),

    #[error("ssh authentication failed: {0}")]
    Authentication(String),

    #[error("ssh channel error: {0}")]
    Channel(String),

    #[error("terminal open failed: {0}")]
    TerminalOpen(String),

    #[error("terminal write failed: {0}")]
    TerminalWrite(String),

    #[error("terminal resize failed: {0}")]
    TerminalResize(String),

    #[error("file operation failed: {0}")]
    FileOperation(String),

    #[error("path validation failed: {0}")]
    PathValidation(String),

    #[error("transfer limit exceeded: {0}")]
    TransferLimit(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("device timeout: {0}")]
    Timeout(String),

    #[error("device unavailable: {0}")]
    Unavailable(String),

    #[error("device I/O error: {0}")]
    Io(#[from] io::Error),
}

impl From<DeviceError> for AdapterError {
    fn from(e: DeviceError) -> Self {
        AdapterError::Ssh(e.to_string())
    }
}

pub type DeviceResult<T> = Result<T, DeviceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let adapter_err: AdapterError = io_err.into();
        let msg = format!("{}", adapter_err);
        assert!(
            msg.contains("IO error"),
            "Display should contain 'IO error', got: {}",
            msg
        );
    }

    #[test]
    fn http_variant_display() {
        let err = AdapterError::Http("bad gateway".to_string());
        assert_eq!(format!("{}", err), "HTTP error: bad gateway");
    }

    #[test]
    fn network_variant_display() {
        let err = AdapterError::Network("connection refused".to_string());
        assert_eq!(format!("{}", err), "Network error: connection refused");
    }

    #[test]
    fn timeout_variant_display() {
        let err = AdapterError::Timeout("30s exceeded".to_string());
        assert_eq!(format!("{}", err), "Timeout: 30s exceeded");
    }

    #[test]
    fn result_ok_and_err() {
        let ok: AdapterResult<i32> = Ok(42);
        assert!(ok.is_ok());
        let err: AdapterResult<i32> = Err(AdapterError::Ssh("auth failed".into()));
        assert!(err.is_err());
    }

    #[test]
    fn device_error_display() {
        let err = DeviceError::NotFound("node-123".to_string());
        assert!(err.to_string().contains("node-123"));
    }

    #[test]
    fn device_error_into_adapter_error() {
        let device_err = DeviceError::Connection("refused".to_string());
        let adapter_err: AdapterError = device_err.into();
        assert!(matches!(adapter_err, AdapterError::Ssh(_)));
    }

    #[test]
    fn device_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe gone");
        let device_err: DeviceError = io_err.into();
        assert!(matches!(device_err, DeviceError::Io(_)));
    }

    #[test]
    fn device_error_is_std_error() {
        let err = DeviceError::Authentication("bad key".to_string());
        let _: &dyn std::error::Error = &err;
    }
}
