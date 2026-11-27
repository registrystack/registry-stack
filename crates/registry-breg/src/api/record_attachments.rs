// SPDX-License-Identifier: Apache-2.0

//! Record attachment downloads. A slot is readable only through the record
//! type's own `get` authority and the selected profile's `readableAttachments`
//! grant. Every other case answers the same concealed refusal.
use super::*;
use base64::Engine as _;

pub(super) fn routes(service: &HttpService) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    for route in &service.registry.routes().routes {
        if route.operation != Operation::Get || read_path_for_route(service, route).is_some() {
            continue;
        }
        if service
            .registry
            .entities()
            .get(&route.entity_id)
            .is_some_and(|entity| !entity.attachments.is_empty())
        {
            app = app.route(
                &format!("{}/attachments/{{slot_id}}", route.path),
                get(download).layer(Extension(route.clone())),
            );
        }
    }
    app
}

async fn download(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let record_id = path.get("record_id");
    let declared_slot = path.get("slot_id").and_then(|slot| {
        service
            .registry
            .entities()
            .get(&route.entity_id)?
            .attachments
            .get_key_value(slot)
            .map(|(id, _)| id.as_str())
    });
    let mut audit_route = route.clone();
    audit_route.id = crate::attachment::record_attachment_operation_id(&route.id, declared_slot);
    let options = match parse_options(raw_query.as_deref()) {
        Ok(options) => options,
        Err(()) => {
            return audited_known_read_refusal(
                &service,
                &audit_route,
                &claims,
                record_id,
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let mut surface = match super::authorize_route_with_reason(&service, &route, &claims, &options)
    {
        Ok(surface) => surface,
        Err(refusal) => {
            return audited_read_concealment(
                &service,
                &audit_route,
                &options,
                &claims,
                record_id,
                &correlation,
                refusal,
            )
            .await;
        }
    };
    if let Err(binding) = surface
        .context
        .bind_access_attribution(surface.response_entity, &headers)
    {
        return audited_read_refusal(
            &service,
            &audit_route,
            &surface,
            record_id,
            access_binding_refusal(binding),
            &correlation,
        )
        .await;
    }
    let slot_id = path.get("slot_id");
    let granted = slot_id.is_some_and(|slot| {
        surface.entity.attachments.contains_key(slot)
            && surface
                .entity
                .access_profiles
                .get(surface.context.selected_profile())
                .is_some_and(|profile| profile.readable_attachments.contains(slot))
    });
    // The attachment row-level policy needs a principal, so a principal-less
    // caller is refused here rather than by an empty database answer.
    let refused_check = if claims.principal().is_none() {
        Some(FailedCheck::TokenClaims)
    } else if record_id.is_none_or(|id| !valid_canonical_record_uuid(id)) {
        Some(FailedCheck::Visibility)
    } else if !granted {
        Some(FailedCheck::Operation)
    } else {
        None
    };
    if let Some(check) = refused_check {
        return audited_read_refusal(
            &service,
            &audit_route,
            &surface,
            record_id,
            concealed(check),
            &correlation,
        )
        .await;
    }
    let request = RecordReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        context: surface.context,
        selected_fields: BTreeSet::new(),
        representation: CursorRepresentation::Json,
        adapter: CursorAdapter::Native,
        adapter_origin: None,
        geojson_next_link_prefix: None,
        kind: RecordReadKind::Get {
            id: record_id.expect("validated record id").clone(),
        },
        maximum_records: 1,
        correlation: correlation.clone(),
    };
    match service
        .records
        .record_attachment(request, slot_id.expect("granted slot").clone())
        .await
    {
        Ok(Some(held)) => attachment_response(held),
        Ok(None) => concealed(FailedCheck::Visibility),
        Err(_) => unavailable(),
    }
}

/// The stored bytes with the digest recorded when the file was attached. A
/// stored digest that is not a SHA-256 hex value fails closed.
fn attachment_response(held: HeldRecordAttachment) -> Response {
    let Some(digest) = representation_digest(&held.sha256) else {
        return unavailable();
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, held.response.content_type())
        .header("repr-digest", digest)
        .header(
            "content-disposition",
            crate::attachment::DOWNLOAD_CONTENT_DISPOSITION,
        )
        .header("x-content-type-options", "nosniff")
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization")
        .body(Body::from(held.response.body().to_vec()))
        .unwrap_or_else(|_| unavailable())
}

/// RFC 9530 `Repr-Digest` for a lowercase hex SHA-256 digest.
fn representation_digest(sha256: &str) -> Option<String> {
    let bytes = hex::decode(sha256).ok().filter(|bytes| bytes.len() == 32)?;
    Some(format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

/// Only `accessProfile` is accepted, once.
fn parse_options(raw: Option<&str>) -> Result<QueryOptions, ()> {
    let mut profile = None;
    if raw.is_some_and(|value| value.len() > 2048) {
        return Err(());
    }
    for pair in raw
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (name, value) = pair.split_once('=').ok_or(())?;
        let name = percent_decode(name).map_err(|_| ())?;
        let value = percent_decode(value).map_err(|_| ())?;
        match name.as_str() {
            "accessProfile" if profile.is_none() => profile = Some(value),
            _ => return Err(()),
        }
    }
    let mut options = QueryOptions::default();
    options.parsed.access_profile = profile;
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representation_digest_encodes_the_stored_hex_digest() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            representation_digest(sha256).as_deref(),
            Some("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
        );
        assert_eq!(representation_digest("not-hex"), None);
        assert_eq!(representation_digest("abcd"), None);
    }

    #[test]
    fn download_query_accepts_one_access_profile_only() {
        assert!(parse_options(None).is_ok());
        assert_eq!(
            parse_options(Some("accessProfile=clerk"))
                .expect("profile")
                .access_profile()
                .map(String::as_str),
            Some("clerk")
        );
        assert!(parse_options(Some("accessProfile=a&accessProfile=b")).is_err());
        assert!(parse_options(Some("fields=name")).is_err());
        assert!(parse_options(Some("accessProfile")).is_err());
    }
}
