use super::*;
use crate::network::Endpoint;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

struct LocalConnector {
    route: SocketAddr,
    addresses: std::sync::Mutex<Vec<std::net::IpAddr>>,
    connections: AtomicUsize,
}
impl Connector for LocalConnector {
    fn resolve<'a>(&'a self, _host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            Ok(self
                .addresses
                .lock()
                .expect("test lock")
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect())
        })
    }
    fn connect(&self, _address: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            self.connections.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(TcpStream::connect(self.route).await?) as Stream)
        })
    }
}
fn policy(host: &str, port: u16) -> NetworkPolicy {
    NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: host.into(),
            port,
        }],
        ..Default::default()
    }
}
async fn echo() -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Ok((address, task))
}
async fn request(address: SocketAddr, head: &str) -> Result<BufReader<TcpStream>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(head.as_bytes()).await?;
    let mut stream = BufReader::new(stream);
    let mut response = String::new();
    loop {
        let count = stream.read_line(&mut response).await?;
        if count == 0 || response.ends_with("\r\n\r\n") {
            break;
        }
    }
    if !response.starts_with("HTTP/1.1 200") {
        bail!("unexpected response: {response}");
    }
    Ok(stream)
}

#[tokio::test]
async fn connect_streams_bytes_and_policy_update_revokes_existing_connections() -> Result<()> {
    let (route, echo_task) = echo().await?;
    let connector = Arc::new(LocalConnector {
        route,
        addresses: std::sync::Mutex::new(vec!["93.184.216.34".parse()?]),
        connections: AtomicUsize::new(0),
    });
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy("allowed.example", 443),
        connector,
        None,
    )
    .await?;
    let mut stream = request(
        broker.local_addr(),
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n",
    )
    .await?;
    stream.get_mut().write_all(b"hello").await?;
    let mut response = [0; 5];
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"hello");
    assert_eq!(
        broker
            .replace_policy(policy("ALLOWED.example.", 443))
            .await?,
        1,
        "an identical normalized policy must preserve active transfers"
    );
    stream.get_mut().write_all(b"again").await?;
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"again");
    assert!(
        broker
            .replace_policy(policy("*.invalid", 443))
            .await
            .is_err()
    );
    stream.get_mut().write_all(b"valid").await?;
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"valid");
    let mut second = request(
        broker.local_addr(),
        "CONNECT allowed.example:443 HTTP/1.1\r\n\r\n",
    )
    .await?;
    assert_eq!(broker.replace_policy(NetworkPolicy::default()).await?, 2);
    let count = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response)).await??;
    assert_eq!(count, 0);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), second.read(&mut response)).await??,
        0
    );
    let mut denied = TcpStream::connect(broker.local_addr()).await?;
    denied
        .write_all(b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        .await?;
    let mut text = String::new();
    denied.read_to_string(&mut text).await?;
    assert!(text.starts_with("HTTP/1.1 403"));
    broker.shutdown().await?;
    echo_task.abort();
    Ok(())
}

struct DelayedResolver {
    entered: Arc<Notify>,
    connections: AtomicUsize,
}
impl Connector for DelayedResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            self.entered.notify_one();
            std::future::pending().await
        })
    }
    fn connect(&self, _address: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            self.connections.fetch_add(1, Ordering::Relaxed);
            bail!("no connect should occur after revocation")
        })
    }
}
#[tokio::test]
async fn policy_revocation_cancels_pending_dns_before_any_connection() -> Result<()> {
    let connector = Arc::new(DelayedResolver {
        entered: Arc::new(Notify::new()),
        connections: AtomicUsize::new(0),
    });
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy("allowed.example", 443),
        connector.clone(),
        None,
    )
    .await?;
    let mut stream = TcpStream::connect(broker.local_addr()).await?;
    stream
        .write_all(b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        .await?;
    tokio::time::timeout(Duration::from_secs(2), connector.entered.notified()).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        broker.replace_policy(NetworkPolicy::default()),
    )
    .await??;
    let mut byte = [0; 1];
    assert_eq!(stream.read(&mut byte).await?, 0);
    assert_eq!(connector.connections.load(Ordering::Relaxed), 0);
    broker.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn dropping_broker_closes_active_tunnels() -> Result<()> {
    let (route, echo_task) = echo().await?;
    let connector = Arc::new(LocalConnector {
        route,
        addresses: std::sync::Mutex::new(vec!["93.184.216.34".parse()?]),
        connections: AtomicUsize::new(0),
    });
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy("allowed.example", 443),
        connector,
        None,
    )
    .await?;
    let mut stream = request(
        broker.local_addr(),
        "CONNECT allowed.example:443 HTTP/1.1\r\n\r\n",
    )
    .await?;
    drop(broker);
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await??,
        0
    );
    echo_task.abort();
    Ok(())
}

#[tokio::test]
async fn mixed_or_rebound_private_dns_answers_are_rejected_before_connect() -> Result<()> {
    let (route, echo_task) = echo().await?;
    let connector = Arc::new(LocalConnector {
        route,
        addresses: std::sync::Mutex::new(vec!["93.184.216.34".parse()?, "127.0.0.1".parse()?]),
        connections: AtomicUsize::new(0),
    });
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy("allowed.example", 443),
        connector.clone(),
        None,
    )
    .await?;
    let mut stream = TcpStream::connect(broker.local_addr()).await?;
    stream
        .write_all(b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        .await?;
    let mut text = String::new();
    stream.read_to_string(&mut text).await?;
    assert!(text.starts_with("HTTP/1.1 403"));
    assert_eq!(connector.connections.load(Ordering::Relaxed), 0);
    broker.shutdown().await?;
    echo_task.abort();
    Ok(())
}

#[tokio::test]
async fn forwards_normal_http_post_with_single_request_framing() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let route = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut stream = BufReader::new(stream);
        let mut head = String::new();
        loop {
            stream.read_line(&mut head).await.expect("header");
            if head.ends_with("\r\n\r\n") {
                break;
            }
        }
        let mut body = [0; 5];
        stream.read_exact(&mut body).await.expect("body");
        assert_eq!(&body, b"hello");
        assert!(head.starts_with("POST /submit HTTP/1.1"));
        assert!(head.contains("Host: allowed.example:80"));
        assert!(!head.contains("Proxy-Authorization"));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.read_u8())
                .await
                .is_err(),
            "request framing must neither forward pipelined bytes nor prematurely half-close TCP"
        );
        stream
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("response");
    });
    let connector = Arc::new(LocalConnector {
        route,
        addresses: std::sync::Mutex::new(vec!["93.184.216.34".parse()?]),
        connections: AtomicUsize::new(0),
    });
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy("allowed.example", 80),
        connector,
        None,
    )
    .await?;
    let mut stream = TcpStream::connect(broker.local_addr()).await?;
    stream.write_all(b"POST http://allowed.example/submit HTTP/1.1\r\nHost: ignored.example\r\nContent-Length: 5\r\nProxy-Authorization: secret\r\n\r\nhelloGET /smuggled HTTP/1.1\r\n\r\n").await?;
    let mut text = String::new();
    stream.read_to_string(&mut text).await?;
    assert!(text.ends_with("ok"));
    server.await?;
    broker.shutdown().await?;
    Ok(())
}
