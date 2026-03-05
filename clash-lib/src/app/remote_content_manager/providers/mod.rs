use async_trait::async_trait;

pub mod proxy_provider;

/// either Proxy or Rule provider
#[async_trait]
pub trait Provider {
    fn name(&self) -> &str;
    // fn vehicle_type(&self) -> ProviderVehicleType;
    // fn typ(&self) -> ProviderType;
    // async fn initialize(&self) -> io::Result<()>;
    // async fn update(&self) -> io::Result<()>;

    // async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>>;
}
