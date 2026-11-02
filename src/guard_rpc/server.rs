use super::{
    DEADLINE, MAX_PROOF, MAX_REQUEST, canonical_uuid,
    config::{FileKind, GuardServerConfig, read_file},
    wire::{
        VerifyRequest, VerifyResponse,
        node_fence_proof_server::{NodeFenceProof, NodeFenceProofServer},
    },
};
use crate::network::hosted_fence::HostedFenceResponse;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use tonic::{
    Request, Response, Status,
    transport::{
        Certificate, Identity, Server, ServerTlsConfig,
        server::{TcpConnectInfo, TlsConnectInfo},
    },
};

type Verify = Arc<dyn Fn(&str, &str) -> Result<HostedFenceResponse> + Send + Sync>;
#[derive(Clone)]
pub(super) struct ProofServer {
    node_uid: String,
    allowed: Arc<BTreeSet<String>>,
    slots: Arc<Semaphore>,
    verify: Verify,
}
impl ProofServer {
    pub(super) fn new(node_uid: String, allowed: Vec<String>, verify: Verify) -> Self {
        Self {
            node_uid,
            allowed: Arc::new(allowed.into_iter().collect()),
            slots: Arc::new(Semaphore::new(16)),
            verify,
        }
    }
    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let certificates = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(TlsConnectInfo::peer_certs)
            .ok_or_else(|| Status::unauthenticated("guard client certificate required"))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("guard client certificate required"))?;
        let digest = format!("{:x}", Sha256::digest(leaf.as_ref()));
        if !self.allowed.contains(&digest) {
            return Err(Status::permission_denied(
                "guard client certificate is not authorized",
            ));
        }
        Ok(())
    }
}
#[tonic::async_trait]
impl NodeFenceProof for ProofServer {
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        canonical_uuid(&request.pod_uid)
            .and_then(|()| canonical_uuid(&request.nonce))
            .map_err(|_| Status::invalid_argument("canonical Pod UID and nonce required"))?;
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("node proof capacity exhausted"))?;
        let verify = self.verify.clone();
        let uid = request.pod_uid.clone();
        let nonce = request.nonce.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify(&uid, &nonce)
        });
        let response = tokio::time::timeout(DEADLINE, task)
            .await
            .map_err(|_| Status::deadline_exceeded("node proof verification deadline"))?
            .map_err(|_| Status::internal("node proof verification failed"))?
            .map_err(|_| Status::failed_precondition("node fence is not verified"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("node clock unavailable"))?
            .as_secs();
        if response.nonce != request.nonce
            || response.proof.binding.pod_uid != request.pod_uid
            || response.proof.binding.node_uid != self.node_uid
            || response.proof.validate(now).is_err()
        {
            return Err(Status::failed_precondition("node fence identity differs"));
        }
        let bytes = serde_json::to_vec(&response)
            .map_err(|_| Status::internal("node proof encoding failed"))?;
        if bytes.len() > MAX_PROOF {
            return Err(Status::resource_exhausted("node proof exceeds bound"));
        }
        Ok(Response::new(VerifyResponse { proof_json: bytes }))
    }
}

pub(super) fn router(server: ProofServer) -> NodeFenceProofServer<ProofServer> {
    NodeFenceProofServer::new(server)
        .max_decoding_message_size(MAX_REQUEST)
        .max_encoding_message_size(MAX_PROOF + 16)
}
pub(super) fn tls(config: &GuardServerConfig) -> Result<ServerTlsConfig> {
    crate::initialize_tls();
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(
            read_file(&config.certificate_file, FileKind::Public)?,
            read_file(&config.private_key_file, FileKind::PrivateKey)?,
        ))
        .client_ca_root(Certificate::from_pem(read_file(
            &config.client_ca_file,
            FileKind::Public,
        )?))
        .client_auth_optional(false))
}

/// Serve only fresh node-fence evidence after validating node-owned configuration.
pub async fn serve(path: &Path, bind_override: Option<std::net::SocketAddr>) -> Result<()> {
    let config = GuardServerConfig::load(path)?;
    let bind = config.bind_address(bind_override)?;
    let node_uid = crate::network::hosted_fence::proof_server_node_uid()?;
    let server = ProofServer::new(
        node_uid,
        config.allowed_client_certificate_sha256.clone(),
        Arc::new(crate::network::hosted_fence::verify_hosted_fence),
    );
    Server::builder()
        .tls_config(tls(&config)?)?
        .concurrency_limit_per_connection(16)
        .add_service(router(server))
        .serve(bind)
        .await?;
    Ok(())
}
