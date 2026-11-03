use super::{
    mediation::Mediation,
    policy::{NetworkPolicy, ValidatedNetworkPolicy, globally_routable},
    proxy,
};
use anyhow::{Context, Result, bail};
use futures::future::BoxFuture;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, RwLock, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

pub(super) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(super) type Stream = Box<dyn Io>;
pub(super) trait Connector: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>>;
    fn connect(&self, address: SocketAddr) -> BoxFuture<'_, Result<Stream>>;
    fn cancellation(&self) -> CancellationToken {
        CancellationToken::new()
    }
}
pub(super) struct SystemConnector;
impl Connector for SystemConnector {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
            let local = if_addrs::get_if_addrs()?;
            if addresses
                .iter()
                .any(|address| local.iter().any(|interface| interface.ip() == address.ip()))
            {
                bail!("DNS answer includes a node-local address");
            }
            Ok(addresses)
        })
    }
    fn connect(&self, address: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            if if_addrs::get_if_addrs()?
                .iter()
                .any(|interface| interface.ip() == address.ip())
            {
                bail!("node-local destinations are forbidden");
            }
            Ok(Box::new(TcpStream::connect(address).await?) as Stream)
        })
    }
}

struct Generation {
    policy: ValidatedNetworkPolicy,
    number: u64,
    cancel: CancellationToken,
    active: AtomicUsize,
    drained: Notify,
}
struct Lease(Arc<Generation>);
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_waiters();
        }
    }
}
impl Generation {
    async fn wait_drained(&self) {
        loop {
            let changed = self.drained.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}
enum GenerationState {
    Active(Arc<Generation>),
    Revoking(Arc<Generation>),
}
struct State {
    current: RwLock<GenerationState>,
    update: Mutex<()>,
    shutdown: CancellationToken,
    connector: Arc<dyn Connector>,
    mediation: Option<Arc<Mediation>>,
}

/// A host-side proxy whose allowlist is distinct from the guest network fence.
pub struct BrokerHandle {
    address: SocketAddr,
    state: Arc<State>,
    task: Option<JoinHandle<()>>,
}
impl BrokerHandle {
    pub async fn active_connections(&self) -> usize {
        let current = self.state.current.read().await;
        match &*current {
            GenerationState::Active(generation) | GenerationState::Revoking(generation) => {
                generation.active.load(Ordering::Acquire)
            }
        }
    }
    pub async fn snapshot(&self) -> Result<(u64, NetworkPolicy)> {
        if self.state.shutdown.is_cancelled() {
            bail!("broker has stopped");
        }
        let current = self.state.current.read().await;
        match &*current {
            GenerationState::Active(generation) => {
                Ok((generation.number, generation.policy.normalized()))
            }
            GenerationState::Revoking(_) => bail!("broker is revoking a policy generation"),
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    /// Provider credential mediation bound to this sandbox, if configured.
    pub fn mediation(&self) -> Option<&Arc<Mediation>> {
        self.state.mediation.as_ref()
    }
    /// Revoke and close every old-generation connection before publishing a new policy.
    pub async fn replace_policy(&self, policy: NetworkPolicy) -> Result<u64> {
        self.replace_policy_inner(policy, false).await
    }
    pub(super) async fn deny_and_drain(&self) -> Result<u64> {
        if let Some(mediation) = &self.state.mediation {
            mediation.revoke();
        }
        self.replace_policy_inner(NetworkPolicy::default(), true)
            .await
    }
    async fn replace_policy_inner(&self, policy: NetworkPolicy, force: bool) -> Result<u64> {
        let validated = policy.validate()?;
        let _guard = self.state.update.lock().await;
        if self.state.shutdown.is_cancelled() {
            bail!("broker has stopped");
        }
        if !force {
            let current = self.state.current.read().await;
            if let GenerationState::Active(generation) = &*current
                && generation.policy == validated
            {
                return Ok(generation.number);
            }
        }
        let old = {
            let mut current = self.state.current.write().await;
            let old = match &*current {
                GenerationState::Active(old) | GenerationState::Revoking(old) => old.clone(),
            };
            *current = GenerationState::Revoking(old.clone());
            old
        };
        old.cancel.cancel();
        old.wait_drained().await;
        if self.state.shutdown.is_cancelled() {
            bail!("broker stopped during policy update");
        }
        let number = old
            .number
            .checked_add(1)
            .context("policy generation overflow")?;
        *self.state.current.write().await = GenerationState::Active(Arc::new(Generation {
            policy: validated,
            number,
            cancel: CancellationToken::new(),
            active: AtomicUsize::new(0),
            drained: Notify::new(),
        }));
        Ok(number)
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.state.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }
}
impl Drop for BrokerHandle {
    fn drop(&mut self) {
        self.state.shutdown.cancel();
        if let Some(mediation) = &self.state.mediation {
            mediation.revoke();
        }
    }
}

/// Bind on a private host address. The caller must install the interface fence
/// before exposing the guest network; this function alone is not isolation.
pub async fn bind_broker(
    address: SocketAddr,
    policy: NetworkPolicy,
    mediation: Option<Mediation>,
) -> Result<BrokerHandle> {
    bind_with_connector(address, policy, Arc::new(SystemConnector), mediation).await
}
pub(super) async fn bind_with_connector(
    address: SocketAddr,
    policy: NetworkPolicy,
    connector: Arc<dyn Connector>,
    mediation: Option<Mediation>,
) -> Result<BrokerHandle> {
    if address.ip().is_unspecified()
        || address.ip().is_multicast()
        || globally_routable(address.ip())
    {
        bail!("broker must bind a specific private host address");
    }
    let generation = Generation {
        policy: policy.validate()?,
        number: 1,
        cancel: CancellationToken::new(),
        active: AtomicUsize::new(0),
        drained: Notify::new(),
    };
    let listener = TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let state = Arc::new(State {
        current: RwLock::new(GenerationState::Active(Arc::new(generation))),
        update: Mutex::new(()),
        shutdown: CancellationToken::new(),
        connector,
        mediation: mediation.map(Arc::new),
    });
    let runner = state.clone();
    let task = tokio::spawn(async move {
        serve(listener, runner).await;
    });
    Ok(BrokerHandle {
        address,
        state,
        task: Some(task),
    })
}
async fn serve(listener: TcpListener, state: Arc<State>) {
    let permits = Arc::new(Semaphore::new(128));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            ()=state.shutdown.cancelled()=>break,
            accepted=listener.accept()=>{
                let Ok((socket,peer))=accepted else{break;};
                let Ok(permit)=permits.clone().try_acquire_owned() else{drop(socket);continue;};
                let guard=state.current.read().await;
                let GenerationState::Active(generation)=&*guard else{drop(socket);continue;};let generation=generation.clone();
                generation.active.fetch_add(1,Ordering::AcqRel);let lease=Lease(generation.clone());drop(guard);
                let connector=state.connector.clone();let mediation=state.mediation.clone();let shutdown=state.shutdown.clone();let authorization=connector.cancellation();
                tasks.spawn(async move{let _permit=permit;let _lease=lease;tokio::select!{
                    ()=shutdown.cancelled()=>{},()=generation.cancel.cancelled()=>{},()=authorization.cancelled()=>{},
                    result=connection(socket,peer,&generation.policy,connector.as_ref(),mediation.as_deref())=>{if let Err(error)=result{tracing::debug!(%error,"broker connection ended");}}
                }});
            }
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
async fn reject(writer: &mut (impl AsyncWrite + Unpin), status: &str) -> Result<()> {
    writer
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    writer.shutdown().await?;
    Ok(())
}
async fn connection(
    socket: TcpStream,
    peer: SocketAddr,
    policy: &ValidatedNetworkPolicy,
    connector: &dyn Connector,
    mediation: Option<&Mediation>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let request =
        match tokio::time::timeout(Duration::from_secs(15), proxy::read_head(&mut reader)).await {
            Ok(Ok(request)) => request,
            _ => return reject(&mut writer, "400 Bad Request").await,
        };
    if !policy.allows(&request.target.host, request.target.port) {
        tracing::info!(host=%request.target.host,port=request.target.port,"egress destination denied by policy");
        return reject(&mut writer, "403 Forbidden").await;
    }
    let inspection = policy.inspection(&request.target.host, request.target.port);
    let mediation = match (inspection, mediation) {
        (None, _) => None,
        // Credential injection requires TLS through CONNECT, from this guest only.
        (Some(access), Some(mediation))
            if request.forward.is_none()
                && mediation.inspects()
                && mediation.admits_peer(peer.ip()) =>
        {
            Some((access, mediation))
        }
        (Some(_), _) => {
            tracing::info!(host=%request.target.host,port=request.target.port,"inspected destination refused outside its guest tunnel");
            return reject(&mut writer, "403 Forbidden").await;
        }
    };
    let addresses = match connector
        .resolve(&request.target.host, request.target.port)
        .await
    {
        Ok(addresses) => addresses,
        Err(_) => return reject(&mut writer, "502 Bad Gateway").await,
    };
    if addresses.is_empty()
        || addresses.iter().any(|address| {
            address.port() != request.target.port || !globally_routable(address.ip())
        })
    {
        return reject(&mut writer, "403 Forbidden").await;
    }
    let mut upstream = None;
    for address in addresses {
        if let Ok(stream) = connector.connect(address).await {
            upstream = Some(stream);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        return reject(&mut writer, "502 Bad Gateway").await;
    };
    if let Some((access, mediation)) = mediation {
        writer
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let client = tokio::io::join(reader, writer);
        return mediation
            .relay(
                client,
                upstream,
                &request.target.host,
                request.target.port,
                access,
            )
            .await;
    }
    if let Some(head) = request.forward {
        upstream.write_all(&head).await?;
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        let body = proxy::forward_body(&mut reader, &mut upstream_write, request.body);
        let response = tokio::io::copy(&mut upstream_read, &mut writer);
        tokio::pin!(body, response);
        tokio::select! {result=&mut response=>{result?;},result=&mut body=>{result?;response.await?;}}
    } else {
        writer
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        let upload = async {
            tokio::io::copy(&mut reader, &mut upstream_write).await?;
            upstream_write.shutdown().await
        };
        let download = async {
            tokio::io::copy(&mut upstream_read, &mut writer).await?;
            writer.shutdown().await
        };
        tokio::try_join!(upload, download)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
