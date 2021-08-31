#![allow(clippy::type_complexity)]

use std::{
    sync::Arc, rc::Rc,
};
use std::ops::{Deref, DerefMut};
use futures_util::future::{ok, FutureExt as _, LocalBoxFuture, Ready};

use actix_service::{Service, Transform};
use actix_web::{
    body::AnyBody, dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, HttpResponse,
    Result,
};

use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};

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
pub struct CasbinService {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinService {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinService {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinService {
        CasbinService { enforcer: e }
    }
}

impl<S> Transform<S, ServiceRequest> for CasbinService
    where
        S: Service<ServiceRequest, Response=ServiceResponse<AnyBody>, Error=Error> + 'static,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    type Transform = CasbinMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CasbinMiddleware {
            enforcer: self.enforcer.clone(),
            service: Rc::new(service),
        })
    }
}

impl Deref for CasbinService {
    type Target = Arc<RwLock<CachedEnforcer>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for CasbinService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

pub struct CasbinMiddleware<S> {
    service: Rc<S>,
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl<S> Service<ServiceRequest> for CasbinMiddleware<S>
    where
        S: Service<ServiceRequest, Response=ServiceResponse<AnyBody>, Error=Error> + 'static,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();

        let path = req.path().to_string();
        let action = req.method().as_str().to_string();
        let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
        let service = Rc::clone(&self.service);

        async move {
            let subject = match option_vals {
                None => return Ok(req.into_response(HttpResponse::Unauthorized().finish())),
                Some(v) => v.subject
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