// SPDX-License-Identifier: Apache-2.0
// Characterization coverage for static Notary route security policy.

#[derive(Clone, Copy, Debug)]
enum CharacterizedListener {
    Public,
    Admin,
}

#[derive(Clone, Copy, Debug)]
enum CharacterizedMethod {
    Get,
    Post,
}

impl CharacterizedMethod {
    fn unsupported_method(self) -> Method {
        match self {
            Self::Get => Method::POST,
            Self::Post => Method::GET,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CharacterizedAuth {
    Exempt,
    Protected,
    ConfigurableOpenApi,
}

#[derive(Clone, Copy, Debug)]
struct RouteSecurityCharacterization {
    matched_path: &'static str,
    sample_path: &'static str,
    listener: CharacterizedListener,
    method: CharacterizedMethod,
    auth: CharacterizedAuth,
    wallet_cors: bool,
    proof_precheck_before_auth: bool,
}

#[tokio::test]
async fn static_api_routes_preserve_listener_and_middleware_security_policy() {
    use CharacterizedAuth::{ConfigurableOpenApi, Exempt, Protected};
    use CharacterizedListener::{Admin, Public};
    use CharacterizedMethod::{Get, Post};

    let routes = [
        RouteSecurityCharacterization {
            matched_path: "/healthz",
            sample_path: "/healthz",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/ready",
            sample_path: "/ready",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/openapi.json",
            sample_path: "/openapi.json",
            listener: Public,
            method: Get,
            auth: ConfigurableOpenApi,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/docs",
            sample_path: "/docs",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/docs/scalar.js",
            sample_path: "/docs/scalar.js",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/.well-known/evidence-service",
            sample_path: "/.well-known/evidence-service",
            listener: Public,
            method: Get,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/.well-known/evidence/jwks.json",
            sample_path: "/.well-known/evidence/jwks.json",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/.well-known/openid-credential-issuer",
            sample_path: "/.well-known/openid-credential-issuer",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/credentials/{*vct_path}",
            sample_path: "/credentials/person-is-alive",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/.well-known/vct/{*vct_path}",
            sample_path: "/.well-known/vct/person-is-alive",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/credential-offer",
            sample_path: "/oid4vci/credential-offer",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/offer/start",
            sample_path: "/oid4vci/offer/start",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/offer/callback",
            sample_path: "/oid4vci/offer/callback",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/token",
            sample_path: "/oid4vci/token",
            listener: Public,
            method: Post,
            auth: Exempt,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/nonce",
            sample_path: "/oid4vci/nonce",
            listener: Public,
            method: Post,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/oid4vci/credential",
            sample_path: "/oid4vci/credential",
            listener: Public,
            method: Post,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: true,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/claims",
            sample_path: "/v1/claims",
            listener: Public,
            method: Get,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/claims/{claim_id}",
            sample_path: "/v1/claims/person-is-alive",
            listener: Public,
            method: Get,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/formats",
            sample_path: "/v1/formats",
            listener: Public,
            method: Get,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/evaluations",
            sample_path: "/v1/evaluations",
            listener: Public,
            method: Post,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/batch-evaluations",
            sample_path: "/v1/batch-evaluations",
            listener: Public,
            method: Post,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/evaluations/{evaluation_id}/render",
            sample_path: "/v1/evaluations/evaluation-1/render",
            listener: Public,
            method: Post,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/credentials",
            sample_path: "/v1/credentials",
            listener: Public,
            method: Post,
            auth: Protected,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/v1/credentials/{credential_id}/status",
            sample_path: "/v1/credentials/credential-1/status",
            listener: Public,
            method: Get,
            auth: Exempt,
            wallet_cors: true,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/admin/v1/capabilities",
            sample_path: "/admin/v1/capabilities",
            listener: Admin,
            method: Get,
            auth: Protected,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/admin/v1/posture",
            sample_path: "/admin/v1/posture",
            listener: Admin,
            method: Get,
            auth: Protected,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/admin/v1/reload",
            sample_path: "/admin/v1/reload",
            listener: Admin,
            method: Post,
            auth: Protected,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
        RouteSecurityCharacterization {
            matched_path: "/admin/v1/credentials/{credential_id}/status",
            sample_path: "/admin/v1/credentials/credential-1/status",
            listener: Admin,
            method: Post,
            auth: Protected,
            wallet_cors: false,
            proof_precheck_before_auth: false,
        },
    ];

    let public = TestServer::new(crate::api::public_router());
    let admin = TestServer::new(crate::api::admin_router());
    let protected_openapi = AuthExemptionPolicy {
        openapi_requires_auth: true,
    };
    let public_openapi = AuthExemptionPolicy {
        openapi_requires_auth: false,
    };

    for route in routes {
        let (mounted, other) = match route.listener {
            Public => (&public, &admin),
            Admin => (&admin, &public),
        };
        let unsupported_method = route.method.unsupported_method();
        assert_eq!(
            mounted
                .method(unsupported_method.clone(), route.sample_path)
                .await
                .status_code(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{} must be mounted on its characterized {:?} listener",
            route.matched_path,
            route.listener
        );
        assert_eq!(
            other
                .method(unsupported_method, route.sample_path)
                .await
                .status_code(),
            StatusCode::NOT_FOUND,
            "{} must not be mounted on the other listener",
            route.matched_path
        );

        let expected_auth = match route.auth {
            Exempt => (true, true),
            Protected => (false, false),
            ConfigurableOpenApi => (false, true),
        };
        assert_eq!(
            (
                is_auth_exempt_path(route.matched_path, protected_openapi),
                is_auth_exempt_path(route.matched_path, public_openapi),
            ),
            expected_auth,
            "{} auth-exemption policy changed",
            route.matched_path
        );
        assert_eq!(
            is_self_attestation_wallet_cors_path(route.sample_path),
            route.wallet_cors,
            "{} wallet CORS classification changed",
            route.matched_path
        );
        assert_eq!(
            crate::api::oid4vci_proof_precheck_applies(route.sample_path),
            route.proof_precheck_before_auth,
            "{} proof-precheck classification changed",
            route.matched_path
        );
    }
}
