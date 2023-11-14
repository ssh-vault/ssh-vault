use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};

pub enum InputSource {
    Stdin,
    File(File),
}

impl InputSource {
    pub fn new(input: Option<String>) -> io::Result<Self> {
        if let Some(filename) = input {
            // Use a file if the filename is not "-" (stdin)
            if filename != "-" {
                return Ok(Self::File(File::open(filename)?));
            }
        }

        Ok(Self::Stdin)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Stdin) && io::stdin().is_terminal()
    }
}

impl Read for InputSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdin => io::stdin().read(buf),
            Self::File(file) => file.read(buf),
        }
    }
}

// OutputDestination is a wrapper around stdout or a temporary file
pub enum OutputDestination {
    Stdout,
    File(File),
}

impl OutputDestination {
    pub fn new(output: Option<String>) -> io::Result<Self> {
        if let Some(filename) = output {
            // Use a file if the filename is not "-" (stdout)
            if filename != "-" {
                return Ok(Self::File(
                    OpenOptions::new().write(true).create(true).open(filename)?,
                ));
            }
        }

        Ok(Self::Stdout)
    }

    pub fn truncate(&self) -> io::Result<()> {
        match self {
            Self::File(file) => file.set_len(0),
            Self::Stdout => Ok(()), // Do nothing for stdout
        }
    }
}

impl Write for OutputDestination {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout => io::stdout().write(buf),
            Self::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout => io::stdout().flush(),
            Self::File(file) => file.flush(),
        }
    }
}

pub fn setup_io(
    input: Option<String>,
    output: Option<String>,
) -> io::Result<(InputSource, OutputDestination)> {
    let input = InputSource::new(input)?;
    let output = OutputDestination::new(output)?;

    Ok((input, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_setup_io() {
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            return;
        }
        let (input, output) = setup_io(None, None).unwrap();
        assert!(input.is_terminal());
        assert!(matches!(output, OutputDestination::Stdout));

        let (input, output) = setup_io(Some("-".to_string()), None).unwrap();
        assert!(input.is_terminal());
        assert!(matches!(output, OutputDestination::Stdout));

        let rs = setup_io(Some("noneexistent".to_string()), None);
        assert!(rs.is_err());
    }

    #[test]
    fn test_setup_io_file() {
        let output_file = NamedTempFile::new().unwrap();

        let (input, output) = setup_io(Some("Cargo.toml".to_string()), None).unwrap();
        assert!(!input.is_terminal());
        assert!(matches!(output, OutputDestination::Stdout));

        let (input, output) =
            setup_io(Some("Cargo.toml".to_string()), Some("-".to_string())).unwrap();
        assert!(!input.is_terminal());
        assert!(matches!(output, OutputDestination::Stdout));

        let (input, output) = setup_io(
            Some("Cargo.toml".to_string()),
            Some(output_file.path().to_str().unwrap().to_string()),
        )
        .unwrap();
        assert!(!input.is_terminal());
        assert!(matches!(output, OutputDestination::File(_)));

        // File is directory
        let rs = setup_io(Some("Cargo.toml".to_string()), Some("/".to_string()));
        assert!(rs.is_err());
    }

    #[test]
    fn test_input_source() {
        let mut input = InputSource::new(Some("Cargo.toml".to_string())).unwrap();
        let mut buf = [0; 1024];
        let n = input.read(&mut buf).unwrap();
        assert!(n > 0);

        let rs = InputSource::new(Some("noneexistent".to_string()));
        assert!(rs.is_err());
    }

    #[test]
    fn test_output_destination() {
        let mut output = OutputDestination::new(Some("-".to_string())).unwrap();
        let n = output.write(b"test").unwrap();
        assert_eq!(n, 4);

        let mut output = OutputDestination::new(None).unwrap();
        let n = output.write(b"test").unwrap();
        assert_eq!(n, 4);

        let output_file = NamedTempFile::new().unwrap();
        let mut output =
            OutputDestination::new(Some(output_file.path().to_str().unwrap().to_string())).unwrap();
        let n = output.write(b"test").unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn test_output_destination_truncate() {
        let mut output_file = NamedTempFile::new().unwrap();
        let mut output =
            OutputDestination::new(Some(output_file.path().to_str().unwrap().to_string())).unwrap();
        let n = output.write(b"test").unwrap();
        assert_eq!(n, 4);

        output.truncate().unwrap();
        let mut buf = [0; 1024];
        let n = output_file.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
