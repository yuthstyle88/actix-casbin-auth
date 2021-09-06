#![allow(clippy::type_complexity)]

use std::{
    error::Error as StdError, future::Future, marker::PhantomData, pin::Pin, rc::Rc,
    sync::Arc,
};

use std::ops::{Deref, DerefMut};
use futures_util::{
    future::{self, FutureExt as _, LocalBoxFuture, TryFutureExt as _},
    ready,
    task::{Context, Poll},
};


use actix_web::{body::{AnyBody, MessageBody}, dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, HttpResponse, HttpMessage};

use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use crate::extractors::{bearer, AuthExtractor};

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[derive(Clone)]
pub struct CasbinVals {
    pub subject: String,
    pub domain: Option<String>,
}

#[derive(Clone)]
pub struct MyEnforcer {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}


impl MyEnforcer {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(MyEnforcer {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> MyEnforcer {
        MyEnforcer { enforcer: e }
    }
}


#[derive(Clone)]
pub struct CasbinService<T, F>
    where
        T: AuthExtractor,
{
    enforcer: Arc<RwLock<CachedEnforcer>>,
    process_fn: Arc<F>,
    _extractor: PhantomData<T>,
}

impl<T, F, O> CasbinService<T, F>
    where
        T: AuthExtractor,
        F: Fn(ServiceRequest, T) -> O,
        O: Future<Output=Result<ServiceRequest, Error>>,
{
    /// Construct `HttpAuthentication` middleware with the provided auth extractor `T` and
    /// validation callback `F`.
    pub fn with_fn(enforcer: Arc<RwLock<CachedEnforcer>>, process_fn: F) -> CasbinService<T, F> {
        CasbinService {
            enforcer,
            process_fn: Arc::new(process_fn),
            _extractor: PhantomData,
        }
    }
}

impl<F, O> CasbinService<bearer::BearerAuth, F>
    where
        F: Fn(ServiceRequest, bearer::BearerAuth) -> O,
        O: Future<Output=Result<ServiceRequest, Error>>,
{
    pub fn bearer(enforcer: Arc<RwLock<CachedEnforcer>>, process_fn: F) -> Self {
        Self::with_fn(enforcer, process_fn)
    }
}

impl<S, B, T, F, O> Transform<S, ServiceRequest> for CasbinService<T, F>
    where
        S: Service<ServiceRequest, Response=ServiceResponse<B>, Error=Error> + 'static,
        S::Future: 'static,
        F: Fn(ServiceRequest, T) -> O + 'static,
        O: Future<Output=Result<ServiceRequest, Error>> + 'static,
        T: AuthExtractor + 'static,
        B: MessageBody + 'static,
        B::Error: StdError,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = CasbinMiddleware<S, F, T>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(CasbinMiddleware {
            enforcer: self.enforcer.clone(),
            service: Rc::new(service),
            process_fn: self.process_fn.clone(),
            _extractor: PhantomData,
        })
    }
}


impl Deref for MyEnforcer {
    type Target = Arc<RwLock<CachedEnforcer>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for MyEnforcer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

#[doc(hidden)]
pub struct CasbinMiddleware<S, F, T> {
    enforcer: Arc<RwLock<CachedEnforcer>>,
    service: Rc<S>,
    process_fn: Arc<F>,
    _extractor: PhantomData<T>,
}

impl<S, B, F, T, O> Service<ServiceRequest> for CasbinMiddleware<S, F, T>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        F: Fn(ServiceRequest, T) -> O + 'static,
        O: Future<Output = Result<ServiceRequest, Error>> + 'static,
        T: AuthExtractor + 'static,
        B: MessageBody + 'static,
        B::Error: StdError,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse, Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();

        let path = req.path().to_string();
        let action = req.method().as_str().to_string();
        let service = Rc::clone(&self.service);

        let process_fn = Arc::clone(&self.process_fn);

        async move {
            let (req, credentials) = match Extract::<T>::new(req).await {
                Ok(req) => req,
                Err((err, req)) => {
                    return Ok(req.error_response(err));
                }
            };

            let req = process_fn(req, credentials).await?;
            let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
            let subject = if let Some(val) = option_vals {
                val.subject
            } else {
                "".to_string()
            };

            let mut lock = cloned_enforcer.write().await;
            match lock.enforce_mut(vec![subject, path, action]) {
                Ok(true) => {
                    drop(lock);
                    service
                        .call(req)
                        .await
                        .map(|res| res.map_body(|_, body| AnyBody::from_message(body)))
                }
                _ => {
                    drop(lock);
                    Ok(req.into_response(HttpResponse::Unauthorized().finish()))
                }
            }
        }.boxed_local()

    }
}

struct Extract<T> {
    req: Option<ServiceRequest>,
    f: Option<LocalBoxFuture<'static, Result<T, Error>>>,
    _extractor: PhantomData<fn() -> T>,
}

impl<T> Extract<T> {
    pub fn new(req: ServiceRequest) -> Self {
        Extract {
            req: Some(req),
            f: None,
            _extractor: PhantomData,
        }
    }
}

impl<T> Future for Extract<T>
    where
        T: AuthExtractor,
        T::Future: 'static,
        T::Error: 'static,
{
    type Output = Result<(ServiceRequest, T), (Error, ServiceRequest)>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.f.is_none() {
            let req = self.req.as_ref().expect("Extract future was polled twice!");
            let f = T::from_service_request(req).map_err(Into::into);
            self.f = Some(f.boxed_local());
        }

        let f = self
            .f
            .as_mut()
            .expect("Extraction future should be initialized at this point");

        let credentials = ready!(f.as_mut().poll(ctx)).map_err(|err| {
            (
                err,
                // returning request allows a proper error response to be created
                self.req.take().expect("Extract future was polled twice!"),
            )
        })?;

        let req = self.req.take().expect("Extract future was polled twice!");
        Poll::Ready(Ok((req, credentials)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractors::bearer::BearerAuth;
    use actix_service::{into_service, Service};
    use actix_web::error;
    use actix_web::test::TestRequest;

    /// This is a test for https://github.com/actix/actix-extras/issues/10
    #[actix_rt::test]
    async fn test_middleware_panic() {
        let middleware = CasbinMiddleware {
            enforcer: Arc::new(()),
            service: Rc::new(into_service(|_: ServiceRequest| async move {
                actix_rt::time::sleep(std::time::Duration::from_secs(1)).await;
                Err::<ServiceResponse, _>(error::ErrorBadRequest("error"))
            })),
            process_fn: Arc::new(|req, _: BearerAuth| async { Ok(req) }),
            _extractor: PhantomData,
        };

        let req = TestRequest::get()
            .append_header(("Authorization", "Bearer 1"))
            .to_srv_request();

        let f = middleware.call(req).await;

        let _res = futures_util::future::lazy(|cx| middleware.poll_ready(cx)).await;

        assert!(f.is_err());
    }

    /// This is a test for https://github.com/actix/actix-extras/issues/10
    #[actix_rt::test]
    async fn test_middleware_panic_several_orders() {
        let middleware = CasbinMiddleware {
            enforcer: Arc::new(()),
            service: Rc::new(into_service(|_: ServiceRequest| async move {
                actix_rt::time::sleep(std::time::Duration::from_secs(1)).await;
                Err::<ServiceResponse, _>(error::ErrorBadRequest("error"))
            })),
            process_fn: Arc::new(|req, _: BearerAuth| async { Ok(req) }),
            _extractor: PhantomData,
        };

        let req = TestRequest::get()
            .append_header(("Authorization", "Bearer 1"))
            .to_srv_request();

        let f1 = middleware.call(req).await;

        let req = TestRequest::get()
            .append_header(("Authorization", "Bearer 1"))
            .to_srv_request();

        let f2 = middleware.call(req).await;

        let req = TestRequest::get()
            .append_header(("Authorization", "Bearer 1"))
            .to_srv_request();

        let f3 = middleware.call(req).await;

        let _res = futures_util::future::lazy(|cx| middleware.poll_ready(cx)).await;

        assert!(f1.is_err());
        assert!(f2.is_err());
        assert!(f3.is_err());
    }
}