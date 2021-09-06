# Actix Casbin Middleware

[![Crates.io](https://meritbadge.herokuapp.com/actix-casbin-auth)](https://crates.io/crates/actix-casbin-auth)
[![Docs](https://docs.rs/actix-casbin-auth/badge.svg)](https://docs.rs/actix-casbin-auth)
[![CI](https://github.com/casbin-rs/actix-casbin-auth/workflows/CI/badge.svg)](https://github.com/casbin-rs/actix-casbin-auth/actions)
[![codecov](https://codecov.io/gh/casbin-rs/actix-casbin-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/actix-casbin-auth)

[Casbin](https://github.com/casbin/casbin-rs) access control middleware for [actix-web](https://github.com/actix/actix-web) framework

## Install

Add it to `Cargo.toml`

```rust
actix-rt = "1.1.1"
actix-web = "3.0.2"
actix-casbin= {version = "0.4.2", default-features = false, features = [ "runtime-async-std" ]}
actix-casbin-auth = {version = "0.4.4", default-features = false, features = [ "runtime-async-std" ]}
```

## Requirement

**Casbin only takes charge of permission control**, so you need to implement an `Authentication Middleware` to identify user.

You should put `actix_casbin_auth::CasbinVals` which contains `subject`(username) and `domain`(optional) into [Extension](https://docs.rs/actix-web/2.0.0/actix_web/dev/struct.Extensions.html).

For example:

```rust
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web::http::{HeaderName, HeaderValue};
use crate::constants;
use uuid::Uuid;
use std::str::FromStr;
use models::roles_rules::RolesRules;
use models::rules::Rules;
use models::schema::rules::dsl::rules;
use crate::app::AppContext;
use actix_web::web::Data;
use models::backend_users::BackendUser;
use utils::my_error::MyError;
use actix_casbin_auth::extractors::bearer::BearerAuth;
use actix_casbin_auth::middleware::CasbinVals;

pub async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    let claims = utils::token::decode_token(credentials.token(), &constants::KEY)?;
    let role = claims.role;
    let uuid = claims.user;
    log::info!("UUID: {}", &uuid);
    req.extensions_mut().insert(uuid);
    let vals = CasbinVals {
        subject: role,
        domain: None,
    };
    req.extensions_mut().insert(vals);
    Ok(req)
}

fn is_can_access(path: String, rule_list: Vec<Rules>) -> Result<bool, MyError> {
    for rule in rule_list {
        if path == rule.routes.unwrap() {
            log::info!("Allow Access: {}", path);
            return Ok(true);
        }
    }
    Err(MyError::new(anyhow!("permission_deny")))
}
````


## Example

```rust
use actix_casbin_auth::casbin::{DefaultModel, FileAdapter, Result};
use actix_casbin_auth::CasbinService;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_casbin_auth::casbin::function_map::key_match2;

#[allow(dead_code)]

use actix_casbin_auth::middleware::{MyEnforcer};
use crate::middleware::authentication::validator;

#[actix_rt::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");  //You can also use diesel-adapter or sqlx-adapter

    let casbin_middleware = MyEnforcer::new(m, a).await?;

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .unwrap()
        .matching_fn(Some(key_match2), None);

    HttpServer::new(move || {
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(actix_casbin_auth::middleware::CasbinService::bearer(casbin_middleware.get_enforcer(),validator))    
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/book/{id}", web::get().to(|| HttpResponse::Ok()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    Ok(())
}
```

## License

This project is licensed under

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
