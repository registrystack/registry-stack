// SPDX-License-Identifier: Apache-2.0

//! Read a configured Point collection with a bbox and explicit pagination.
//! See the crate README for the required environment variables.

use std::sync::Arc;

use registry_breg_client::{
    BRegBoundingBox, BRegGeoJsonListRequest, BRegGeoJsonOptions, BaseRegistryClient,
    BaseRegistryClientConfig, StaticToken,
};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("BREG_BASE_URL")?;
    let route = std::env::var("BREG_ENTITY_ROUTE")?;
    let profile = std::env::var("BREG_ACCESS_PROFILE")?;
    let bbox = std::env::var("BREG_BBOX")?;
    let coordinates: Vec<_> = bbox.split(',').collect();
    let [west, south, east, north] = coordinates.as_slice() else {
        return Err("BREG_BBOX requires west,south,east,north".into());
    };
    let bbox = BRegBoundingBox::new(*west, *south, *east, *north)?;
    let mut config = BaseRegistryClientConfig::new(Url::parse(&base_url)?);
    if let Ok(path) = std::env::var("BREG_TOKEN_FILE") {
        let token = std::fs::read_to_string(path)?;
        config = config.with_token_provider(Arc::new(StaticToken::new(token.trim())?));
    }
    let client = BaseRegistryClient::new(config)?;
    let options = BRegGeoJsonOptions::default().access_profile(profile)?;
    let request = BRegGeoJsonListRequest::default()
        .options(options)
        .bbox(bbox)
        .top(20)?;
    let mut page = client.list_geojson_records(&route, &request).await?;
    loop {
        println!("{}", serde_json::to_string(&page.value.value)?);
        let Some(continuation) = page.value.continuation else {
            break;
        };
        page = client.continue_geojson_list(&continuation).await?;
    }
    Ok(())
}
