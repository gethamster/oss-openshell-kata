use super::{
    DEADLINE, MAX_PROOF, MAX_REQUEST, canonical_uuid,
    config::{FileKind, GuardClientConfig, read_file},
    server_name, validate_endpoint,
    wire::{VerifyRequest, node_fence_proof_client::NodeFenceProofClient},
};
use crate::network::hosted_fence::HostedFenceResponse;
use anyhow::{Context, Result, ensure};
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tonic::{
    Request,
    transport::{Certificate, ClientTlsConfig, Endpoint, Identity},
};

/// Read fresh node evidence over a dedicated authenticated read-only connection.
pub async fn verify_remote(
    endpoint: SocketAddr,
    node_uid: &str,
    config: &GuardClientConfig,
    pod_uid: &str,
    nonce: &str,
) -> Result<HostedFenceResponse> {
    validate_endpoint(endpoint)?;
    tokio::time::timeout(
        DEADLINE,
        request(endpoint, node_uid, config, pod_uid, nonce),
    )
    .await
    .context("node proof total deadline exceeded")?
}
pub(super) async fn request(
    endpoint: SocketAddr,
    node_uid: &str,
    config: &GuardClientConfig,
    pod_uid: &str,
    nonce: &str,
) -> Result<HostedFenceResponse> {
    crate::initialize_tls();
    canonical_uuid(pod_uid)?;
    canonical_uuid(nonce)?;
    config.validate()?;
    let tls = ClientTlsConfig::new()
        .domain_name(server_name(node_uid)?)
        .ca_certificate(Certificate::from_pem(read_file(
            &config.server_ca_file,
            FileKind::Public,
        )?))
        .identity(Identity::from_pem(
            read_file(&config.certificate_file, FileKind::Public)?,
            read_file(&config.private_key_file, FileKind::PrivateKey)?,
        ));
    let channel = Endpoint::from_shared(format!("https://{endpoint}"))?
        .connect_timeout(DEADLINE)
        .timeout(DEADLINE)
        .tls_config(tls)?
        .connect()
        .await
        .context("connecting to authenticated node proof service")?;
    let mut client = NodeFenceProofClient::new(channel)
        .max_decoding_message_size(MAX_PROOF + 16)
        .max_encoding_message_size(MAX_REQUEST);
    let mut request = Request::new(VerifyRequest {
        pod_uid: pod_uid.into(),
        nonce: nonce.into(),
    });
    request.set_timeout(DEADLINE);
    let result = tokio::time::timeout(DEADLINE, client.verify(request))
        .await
        .context("node proof deadline exceeded")??
        .into_inner();
    decode(&result.proof_json, node_uid, pod_uid, nonce)
}
pub(super) fn decode(
    bytes: &[u8],
    node_uid: &str,
    pod_uid: &str,
    nonce: &str,
) -> Result<HostedFenceResponse> {
    ensure!(bytes.len() <= MAX_PROOF, "oversized node proof");
    let response: HostedFenceResponse = serde_json::from_slice(bytes)?;
    ensure!(
        response.nonce == nonce
            && response.proof.binding.pod_uid == pod_uid
            && response.proof.binding.node_uid == node_uid,
        "node proof response identity differs"
    );
    response
        .proof
        .validate(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(response)
}
