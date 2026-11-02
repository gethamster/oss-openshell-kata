use openshell_kata::proto::openshell::{sandbox::v1 as s, v1 as o};
use prost::Message;
use std::{
    convert::Infallible,
    marker::PhantomData,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::{Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Response, Status,
    codegen::{Body, BoxFuture, Service, StdError, http},
};

#[derive(Default)]
pub struct State {
    pub snapshot: Mutex<s::GetSandboxConfigResponse>,
    pub providers: Mutex<o::GetSandboxProviderEnvironmentResponse>,
    pub reports: Mutex<Vec<o::ReportSandboxConfigurationRequest>>,
    pub headers: Mutex<Vec<String>>,
    pub control: Mutex<Option<mpsc::Sender<Result<o::GatewayMessage, Status>>>>,
    pub relay_data: Mutex<Vec<u8>>,
    pub retry_configs: AtomicUsize,
    pub provider_races: AtomicUsize,
    pub refresh_calls: AtomicUsize,
    pub initial_expires: Mutex<Option<std::time::Instant>>,
    pub refreshed: Notify,
    pub relayed: Notify,
}

impl State {
    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !matches!(
            token,
            "Bearer initial-credential"
                | "Bearer refreshed-credential"
                | "Bearer fresh-start-credential"
        ) {
            return Err(Status::unauthenticated(
                "fixture requires a sandbox credential",
            ));
        }
        if token == "Bearer initial-credential"
            && self
                .initial_expires
                .lock()
                .expect("fixture expiration")
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(Status::unauthenticated("fixture launch credential expired"));
        }
        self.headers
            .lock()
            .expect("fixture headers")
            .push(token.into());
        Ok(())
    }
}

#[derive(Clone)]
pub struct Gateway(pub Arc<State>);
impl tonic::server::NamedService for Gateway {
    const NAME: &'static str = "openshell.v1.OpenShell";
}

type UnaryHandler<Q, A> = fn(&State, Request<Q>) -> Result<A, Status>;
struct Unary<Q, A> {
    state: Arc<State>,
    handler: UnaryHandler<Q, A>,
    marker: PhantomData<fn(Q) -> A>,
}
impl<Q: Send + 'static, A: Send + 'static> tonic::server::UnaryService<Q> for Unary<Q, A> {
    type Response = A;
    type Future = BoxFuture<Response<A>, Status>;
    fn call(&mut self, request: Request<Q>) -> Self::Future {
        let state = self.state.clone();
        let handler = self.handler;
        Box::pin(async move {
            state.authorize(&request)?;
            handler(&state, request).map(Response::new)
        })
    }
}

fn unary<B, Q, A>(
    state: Arc<State>,
    request: http::Request<B>,
    handler: UnaryHandler<Q, A>,
) -> BoxFuture<http::Response<tonic::body::Body>, Infallible>
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
    Q: Message + Default + Send + 'static,
    A: Message + Default + Send + 'static,
{
    Box::pin(async move {
        let method = Unary {
            state,
            handler,
            marker: PhantomData,
        };
        Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
            .unary(method, request)
            .await)
    })
}

struct Supervisor(Arc<State>);
impl tonic::server::StreamingService<o::SupervisorMessage> for Supervisor {
    type Response = o::GatewayMessage;
    type ResponseStream = ReceiverStream<Result<o::GatewayMessage, Status>>;
    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;
    fn call(&mut self, request: Request<tonic::Streaming<o::SupervisorMessage>>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.authorize(&request)?;
            let mut inbound = request.into_inner();
            let (sender, receiver) = mpsc::channel(8);
            *state.control.lock().expect("fixture control") = Some(sender.clone());
            tokio::spawn(async move {
                if let Ok(Some(message)) = inbound.message().await {
                    assert!(matches!(
                        message.payload,
                        Some(o::supervisor_message::Payload::Hello(_))
                    ));
                    let _ = sender
                        .send(Ok(o::GatewayMessage {
                            payload: Some(o::gateway_message::Payload::SessionAccepted(
                                o::SessionAccepted::default(),
                            )),
                        }))
                        .await;
                }
                while inbound.message().await.ok().flatten().is_some() {}
            });
            Ok(Response::new(ReceiverStream::new(receiver)))
        })
    }
}

struct Relay(Arc<State>);
impl tonic::server::StreamingService<o::RelayFrame> for Relay {
    type Response = o::RelayFrame;
    type ResponseStream = ReceiverStream<Result<o::RelayFrame, Status>>;
    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;
    fn call(&mut self, request: Request<tonic::Streaming<o::RelayFrame>>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.authorize(&request)?;
            let mut inbound = request.into_inner();
            let (sender, receiver) = mpsc::channel(8);
            tokio::spawn(async move {
                let initial = inbound
                    .message()
                    .await
                    .expect("relay init request")
                    .expect("relay init");
                assert!(matches!(
                    initial.payload,
                    Some(o::relay_frame::Payload::Init(_))
                ));
                sender
                    .send(Ok(o::RelayFrame {
                        payload: Some(o::relay_frame::Payload::Data(b"through-the-relay".to_vec())),
                    }))
                    .await
                    .expect("relay payload");
                while let Ok(Some(frame)) = inbound.message().await {
                    if let Some(o::relay_frame::Payload::Data(data)) = frame.payload {
                        state
                            .relay_data
                            .lock()
                            .expect("fixture relay bytes")
                            .extend(data);
                        state.relayed.notify_one();
                        break;
                    }
                }
            });
            Ok(Response::new(ReceiverStream::new(receiver)))
        })
    }
}

impl<B> Service<http::Request<B>> for Gateway
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let state = self.0.clone();
        match request.uri().path() {
            "/openshell.v1.OpenShell/GetSandboxConfig" => unary(
                state,
                request,
                |state, _: Request<s::GetSandboxConfigRequest>| {
                    if state
                        .retry_configs
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                            value.checked_sub(1)
                        })
                        .is_ok()
                    {
                        return Err(Status::not_found("configuration not committed yet"));
                    }
                    Ok(state.snapshot.lock().expect("fixture snapshot").clone())
                },
            ),
            "/openshell.v1.OpenShell/GetSandboxProviderEnvironment" => unary(
                state,
                request,
                |state, _: Request<o::GetSandboxProviderEnvironmentRequest>| {
                    if state
                        .provider_races
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                            count.checked_sub(1)
                        })
                        .is_ok()
                    {
                        let mut snapshot = state.snapshot.lock().expect("fixture snapshot");
                        snapshot.provider_env_revision += 1;
                        state
                            .providers
                            .lock()
                            .expect("fixture providers")
                            .provider_env_revision = snapshot.provider_env_revision;
                    }
                    Ok(state.providers.lock().expect("fixture providers").clone())
                },
            ),
            "/openshell.v1.OpenShell/ReportSandboxConfiguration" => unary(
                state,
                request,
                |state, request: Request<o::ReportSandboxConfigurationRequest>| {
                    state
                        .reports
                        .lock()
                        .expect("fixture reports")
                        .push(request.into_inner());
                    Ok(o::ReportSandboxConfigurationResponse::default())
                },
            ),
            "/openshell.v1.OpenShell/RefreshSandboxToken" => unary(
                state,
                request,
                |state, _: Request<o::RefreshSandboxTokenRequest>| {
                    state.refresh_calls.fetch_add(1, Ordering::SeqCst);
                    state.refreshed.notify_one();
                    Ok(o::RefreshSandboxTokenResponse {
                        token: "refreshed-credential".into(),
                        session_id: "fixture-gateway-session".into(),
                        ..Default::default()
                    })
                },
            ),
            "/openshell.v1.OpenShell/ConnectSupervisor" => Box::pin(async move {
                Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .streaming(Supervisor(state), request)
                    .await)
            }),
            "/openshell.v1.OpenShell/RelayStream" => Box::pin(async move {
                Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .streaming(Relay(state), request)
                    .await)
            }),
            _ => Box::pin(async move {
                Ok(http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(tonic::body::Body::empty())
                    .expect("valid gRPC fixture response"))
            }),
        }
    }
}
