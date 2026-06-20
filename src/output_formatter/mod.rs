//! Output formatting module for RustScan.
//!
//! This module provides different output formatters for scan results,
//! including CSV and other structured output formats.

use std::net::SocketAddr;

/// Represents the protocol of a scanned port
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Represents a single port scan result
#[derive(Debug, Clone)]
pub struct PortResult {
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub state: String,
    pub service: String,
    pub version: String,
}

impl PortResult {
    pub fn new(socket: SocketAddr, protocol: Protocol) -> Self {
        Self {
            ip: socket.ip().to_string(),
            port: socket.port(),
            protocol,
            state: "open".to_string(),
            service: String::new(),
            version: String::new(),
        }
    }
}

/// Trait for output writers
pub trait OutputWriter {
    fn write_header(&mut self) -> String;
    fn write_result(&mut self, result: &PortResult) -> String;
    fn write_footer(&mut self) -> String;
}

/// CSV output writer
#[derive(Debug, Default)]
pub struct CsvWriter {
    header_written: bool,
}

impl CsvWriter {
    pub fn new() -> Self {
        Self {
            header_written: false,
        }
    }

    fn escape_field(field: &str) -> String {
        if field.contains(',')
            || field.contains('"')
            || field.contains('\n')
            || field.contains('\r')
        {
            let escaped = field.replace('"', "\"\"");
            format!("\"{}\"", escaped)
        } else {
            field.to_string()
        }
    }
}

impl OutputWriter for CsvWriter {
    fn write_header(&mut self) -> String {
        if self.header_written {
            return String::new();
        }
        self.header_written = true;
        "ip,port,protocol,state,service,version".to_string()
    }

    fn write_result(&mut self, result: &PortResult) -> String {
        let fields = vec![
            Self::escape_field(&result.ip),
            result.port.to_string(),
            result.protocol.to_string(),
            Self::escape_field(&result.state),
            Self::escape_field(&result.service),
            Self::escape_field(&result.version),
        ];
        fields.join(",")
    }

    fn write_footer(&mut self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_csv_header() {
        let mut writer = CsvWriter::new();
        let header = writer.write_header();
        assert_eq!(header, "ip,port,protocol,state,service,version");
    }

    #[test]
    fn test_csv_header_only_written_once() {
        let mut writer = CsvWriter::new();
        let header1 = writer.write_header();
        let header2 = writer.write_header();
        assert_eq!(header1, "ip,port,protocol,state,service,version");
        assert_eq!(header2, "");
    }

    #[test]
    fn test_csv_simple_result() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let result = PortResult::new(socket, Protocol::Tcp);
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,,");
    }

    #[test]
    fn test_csv_udp_protocol() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
        let result = PortResult::new(socket, Protocol::Udp);
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,53,udp,open,,");
    }

    #[test]
    fn test_csv_field_with_comma() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "http, www".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,\"http, www\",");
    }

    #[test]
    fn test_csv_field_with_quotes() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "test\"quote".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,\"test\"\"quote\",");
    }

    #[test]
    fn test_csv_field_with_newline() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.version = "1.0\n2.0".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,,\"1.0\n2.0\"");
    }

    #[test]
    fn test_csv_with_service_and_version() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "https".to_string();
        result.version = "Apache 2.4.41".to_string();
        let line = writer.write_result(&result);
        assert_eq!(
            line,
            "192.168.1.1,443,tcp,open,https,Apache 2.4.41"
        );
    }

    #[test]
    fn test_csv_multiple_results() {
        let mut writer = CsvWriter::new();
        let header = writer.write_header();

        let socket1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let result1 = PortResult::new(socket1, Protocol::Tcp);
        let line1 = writer.write_result(&result1);

        let socket2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let result2 = PortResult::new(socket2, Protocol::Tcp);
        let line2 = writer.write_result(&result2);

        assert_eq!(header, "ip,port,protocol,state,service,version");
        assert_eq!(line1, "127.0.0.1,80,tcp,open,,");
        assert_eq!(line2, "127.0.0.1,443,tcp,open,,");
    }

    #[test]
    fn test_csv_ipv6_address() {
        use std::net::Ipv6Addr;
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let result = PortResult::new(socket, Protocol::Tcp);
        let line = writer.write_result(&result);
        assert_eq!(line, "::1,8080,tcp,open,,");
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }

    #[test]
    fn test_port_result_new() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22);
        let result = PortResult::new(socket, Protocol::Tcp);
        assert_eq!(result.ip, "10.0.0.1");
        assert_eq!(result.port, 22);
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.state, "open");
        assert_eq!(result.service, "");
        assert_eq!(result.version, "");
    }

    #[test]
    fn test_csv_footer_empty() {
        let mut writer = CsvWriter::new();
        let footer = writer.write_footer();
        assert_eq!(footer, "");
    }

    #[test]
    fn test_csv_field_with_carriage_return() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.version = "1.0\r\n2.0".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,,\"1.0\r\n2.0\"");
    }

    #[test]
    fn test_csv_service_with_comma() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "http, www, web".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,\"http, www, web\",");
    }

    #[test]
    fn test_csv_version_with_quotes() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.version = "Apache \"2.4.41\" (Ubuntu)".to_string();
        let line = writer.write_result(&result);
        assert_eq!(
            line,
            "127.0.0.1,80,tcp,open,,\"Apache \"\"2.4.41\"\" (Ubuntu)\""
        );
    }

    #[test]
    fn test_csv_service_with_newline() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "http\nhttps".to_string();
        let line = writer.write_result(&result);
        assert_eq!(line, "127.0.0.1,80,tcp,open,\"http\nhttps\",");
    }

    #[test]
    fn test_csv_both_service_and_version_with_special_chars() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.service = "proxy, http".to_string();
        result.version = "Nginx \"1.18.0\"\n(Ubuntu)".to_string();
        let line = writer.write_result(&result);
        assert_eq!(
            line,
            "192.168.1.1,8080,tcp,open,\"proxy, http\",\"Nginx \"\"1.18.0\"\"\n(Ubuntu)\""
        );
    }

    #[test]
    fn test_csv_ip_field_with_ipv6_colons_not_escaped() {
        use std::net::Ipv6Addr;
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let result = PortResult::new(socket, Protocol::Tcp);
        let line = writer.write_result(&result);
        assert_eq!(line, "2001:db8::1,443,tcp,open,,");
    }

    #[test]
    fn test_csv_all_fields_escaped() {
        let mut writer = CsvWriter::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22);
        let mut result = PortResult::new(socket, Protocol::Tcp);
        result.state = "open, filtered".to_string();
        result.service = "ssh, remote shell".to_string();
        result.version = "OpenSSH \"8.9p1\"\nUbuntu".to_string();
        let line = writer.write_result(&result);
        assert_eq!(
            line,
            "127.0.0.1,22,tcp,\"open, filtered\",\"ssh, remote shell\",\"OpenSSH \"\"8.9p1\"\"\nUbuntu\""
        );
    }
}
