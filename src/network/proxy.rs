use super::policy::{Endpoint, normalize_host};
use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

const MAX_HEAD: usize = 32 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    None,
    Length(u64),
    Chunked,
}
#[derive(Debug)]
pub(crate) struct RequestHead {
    pub target: Endpoint,
    pub forward: Option<Vec<u8>>,
    pub body: Body,
}

pub(crate) async fn read_head<R: AsyncBufRead + Unpin>(input: &mut R) -> Result<RequestHead> {
    parse_head(&read_raw_head(input).await?)
}

async fn read_raw_head<R: AsyncBufRead + Unpin>(input: &mut R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let count = (&mut *input)
            .take(u64::try_from(MAX_HEAD + 1 - bytes.len())?)
            .read_until(b'\n', &mut bytes)
            .await?;
        if count == 0 {
            bail!("incomplete proxy request");
        }
        if bytes.len() > MAX_HEAD {
            bail!("proxy request headers too large");
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
}

/// One origin-form request read from a TLS-terminated CONNECT tunnel.
#[derive(Debug)]
pub(crate) struct InspectedRequest {
    pub method: String,
    pub target: String,
    /// The head to forward: hop-by-hop fields removed, `Connection: close`.
    pub forward: Vec<u8>,
    pub body: Body,
}

/// Read one request whose `Host` must name the tunnel's own authority.
pub(crate) async fn read_inspected_head<R: AsyncBufRead + Unpin>(
    input: &mut R,
    host: &str,
    port: u16,
) -> Result<InspectedRequest> {
    parse_inspected_head(&read_raw_head(input).await?, host, port)
}

/// Framing and hop-by-hop fields of a parsed request head.
struct Framing {
    body: Body,
    connection_fields: BTreeSet<String>,
}

fn framing(request: &httparse::Request<'_, '_>) -> Result<Framing> {
    if request.version != Some(1) && request.version != Some(0) {
        bail!("unsupported HTTP version");
    }
    let mut length = None;
    let mut chunked = false;
    let mut connection_fields = BTreeSet::new();
    for header in request.headers.iter() {
        let value = std::str::from_utf8(header.value)?.trim();
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                bail!("duplicate content length");
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("invalid content length");
            }
            length = Some(value.parse::<u64>()?);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                bail!("unsupported transfer encoding");
            }
            chunked = true;
        }
        if header.name.eq_ignore_ascii_case("connection") {
            for field in value.split(',') {
                connection_fields.insert(field.trim().to_ascii_lowercase());
            }
        }
        if header.name.eq_ignore_ascii_case("upgrade") {
            bail!("use CONNECT for upgraded protocols");
        }
    }
    if length.is_some() && chunked {
        bail!("ambiguous request body framing");
    }
    if connection_fields.contains("content-length")
        || connection_fields.contains("transfer-encoding")
    {
        bail!("connection header cannot remove body framing");
    }
    let body = if chunked {
        Body::Chunked
    } else if let Some(length) = length {
        Body::Length(length)
    } else {
        Body::None
    };
    Ok(Framing {
        body,
        connection_fields,
    })
}

/// Copy end-to-end fields, dropping hop-by-hop and proxy fields.
fn forward_fields(
    forward: &mut Vec<u8>,
    request: &httparse::Request<'_, '_>,
    connection_fields: &BTreeSet<String>,
) {
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "keep-alive"
                | "te"
                | "trailer"
                | "upgrade"
        ) || connection_fields.contains(&name)
        {
            continue;
        }
        forward.extend_from_slice(header.name.as_bytes());
        forward.extend_from_slice(b": ");
        forward.extend_from_slice(header.value);
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"\r\n");
}

fn parse_inspected_head(bytes: &[u8], host: &str, port: u16) -> Result<InspectedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if !request.parse(bytes)?.is_complete() {
        bail!("incomplete request headers");
    }
    let method = request
        .method
        .context("request method required")?
        .to_owned();
    let target = request.path.context("request target required")?.to_owned();
    if method == "CONNECT" || !target.starts_with('/') || target.contains('#') {
        bail!("inspected requests require an origin-form target");
    }
    let framing = framing(&request)?;
    let mut authorities = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let authority = authorities.next().context("Host header required")?;
    if authorities.next().is_some() {
        bail!("duplicate Host header");
    }
    let named = authority_from(std::str::from_utf8(authority.value)?.trim(), Some(port))?;
    if named.host != normalize_host(host)? || named.port != port {
        bail!("Host header does not name the tunnel destination");
    }
    let host_field = if port == 443 {
        named.host.clone()
    } else {
        format!("{}:{port}", named.host)
    };
    let mut forward =
        format!("{method} {target} HTTP/1.1\r\nHost: {host_field}\r\nConnection: close\r\n")
            .into_bytes();
    forward_fields(&mut forward, &request, &framing.connection_fields);
    Ok(InspectedRequest {
        method,
        target,
        forward,
        body: framing.body,
    })
}

fn authority_from(value: &str, default_port: Option<u16>) -> Result<Endpoint> {
    if value.contains('@')
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        bail!("invalid proxy authority");
    }
    let (host, port) = if value.starts_with('[') {
        let close = value.find(']').context("unterminated IPv6 authority")?;
        let port = if value[close + 1..].is_empty() {
            default_port.context("proxy port required")?
        } else {
            value[close + 1..]
                .strip_prefix(':')
                .context("invalid IPv6 authority")?
                .parse()?
        };
        (&value[1..close], port)
    } else if let Some((host, port)) = value.rsplit_once(':') {
        (host, port.parse()?)
    } else {
        (value, default_port.context("proxy port required")?)
    };
    if port == 0 {
        bail!("proxy port must be nonzero");
    }
    Ok(Endpoint {
        host: normalize_host(host)?,
        port,
    })
}

fn parse_head(bytes: &[u8]) -> Result<RequestHead> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if !request.parse(bytes)?.is_complete() {
        bail!("incomplete proxy headers");
    }
    let method = request.method.context("proxy method required")?;
    let target = request.path.context("proxy target required")?;
    let Framing {
        body,
        connection_fields,
    } = framing(&request)?;
    if method == "CONNECT" {
        if !matches!(body, Body::None | Body::Length(0)) {
            bail!("CONNECT cannot have an HTTP request body");
        }
        return Ok(RequestHead {
            target: authority_from(target, None)?,
            forward: None,
            body: Body::None,
        });
    }
    let remaining = target
        .strip_prefix("http://")
        .context("forward requests require an absolute http URL")?;
    if remaining.contains('#') {
        bail!("URL fragments are not request targets");
    }
    let cut = remaining.find(['/', '?']).unwrap_or(remaining.len());
    let destination = authority_from(&remaining[..cut], Some(80))?;
    let path = if cut == remaining.len() {
        "/".to_owned()
    } else if remaining.as_bytes()[cut] == b'?' {
        format!("/{}", &remaining[cut..])
    } else {
        remaining[cut..].to_owned()
    };
    let host = if destination.host.contains(':') {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        format!("{}:{}", destination.host, destination.port)
    };
    let mut forward =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n").into_bytes();
    forward_fields(&mut forward, &request, &connection_fields);
    Ok(RequestHead {
        target: destination,
        forward: Some(forward),
        body,
    })
}

async fn exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: &mut R,
    output: &mut W,
    count: u64,
) -> Result<()> {
    if tokio::io::copy(&mut input.take(count), output).await? != count {
        bail!("HTTP request body ended early");
    }
    Ok(())
}

pub(crate) async fn forward_body<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    input: &mut R,
    output: &mut W,
    body: Body,
) -> Result<()> {
    match body {
        Body::None => {}
        Body::Length(count) => exact(input, output, count).await?,
        Body::Chunked => loop {
            let mut line = Vec::new();
            if (&mut *input)
                .take(8193)
                .read_until(b'\n', &mut line)
                .await?
                == 0
                || line.len() > 8192
                || !line.ends_with(b"\r\n")
            {
                bail!("invalid HTTP chunk header");
            }
            let text = std::str::from_utf8(&line[..line.len() - 2])?;
            let size = u64::from_str_radix(
                text.split(';')
                    .next()
                    .context("chunk size required")?
                    .trim(),
                16,
            )?;
            output.write_all(&line).await?;
            if size == 0 {
                let mut end = [0; 2];
                input.read_exact(&mut end).await?;
                if end != *b"\r\n" {
                    bail!("HTTP trailers are not supported");
                }
                output.write_all(&end).await?;
                break;
            }
            exact(input, output, size).await?;
            let mut end = [0; 2];
            input.read_exact(&mut end).await?;
            if end != *b"\r\n" {
                bail!("invalid chunk delimiter");
            }
            output.write_all(&end).await?;
        },
    }
    // HTTP framing already marks the end of this request. A TCP half-close here
    // makes some real HTTP servers discard the request before replying.
    output.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rewrites_absolute_target_and_removes_proxy_credentials() {
        let head=parse_head(b"GET http://example.com/a?x=1 HTTP/1.1\r\nHost: evil.test\r\nProxy-Authorization: secret\r\nConnection: X-Remove\r\nX-Remove: value\r\n\r\n").expect("valid head");
        let forwarded = String::from_utf8(head.forward.expect("HTTP forwarding")).expect("UTF8");
        assert!(forwarded.contains("GET /a?x=1 HTTP/1.1"));
        assert!(forwarded.contains("Host: example.com:80"));
        assert!(!forwarded.contains("secret"));
        assert!(!forwarded.contains("X-Remove"));
    }
    #[test]
    fn rejects_smuggling_and_nonabsolute_requests() {
        for bytes in [b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",b"GET /local HTTP/1.1\r\nHost: example.com\r\n\r\n"]{assert!(parse_head(bytes).is_err());}
    }
    #[tokio::test]
    async fn chunked_body_stops_before_pipelined_bytes() -> Result<()> {
        let mut input = tokio::io::BufReader::new(&b"4\r\ntest\r\n0\r\n\r\nignored"[..]);
        let (mut output, mut received) = tokio::io::duplex(128);
        forward_body(&mut input, &mut output, Body::Chunked).await?;
        output.shutdown().await?;
        let mut bytes = Vec::new();
        received.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, b"4\r\ntest\r\n0\r\n\r\n");
        let mut remaining = String::new();
        input.read_to_string(&mut remaining).await?;
        assert_eq!(remaining, "ignored");
        Ok(())
    }
    #[tokio::test]
    async fn header_limit_rejects_unterminated_input() {
        let bytes = vec![b'A'; MAX_HEAD + 4096];
        let mut reader = tokio::io::BufReader::new(bytes.as_slice());
        assert!(read_head(&mut reader).await.is_err());
    }
    #[tokio::test]
    async fn malformed_or_ambiguous_body_framing_fails_closed() {
        for bytes in [b"POST http://example.com/ HTTP/1.1\r\nContent-Length: +5\r\n\r\n".as_slice(),b"POST http://example.com/ HTTP/1.1\r\nConnection: Content-Length\r\nContent-Length: 5\r\n\r\n",b"CONNECT user@example.com:443 HTTP/1.1\r\n\r\n"] {assert!(parse_head(bytes).is_err());}
        for (bytes, body) in [
            (b"4\r\nab".as_slice(), Body::Chunked),
            (b"0\r\nUntrusted: trailer\r\n\r\n".as_slice(), Body::Chunked),
            (b"short".as_slice(), Body::Length(20)),
        ] {
            let mut input = tokio::io::BufReader::new(bytes);
            let mut output = tokio::io::sink();
            assert!(forward_body(&mut input, &mut output, body).await.is_err());
        }
    }
}
