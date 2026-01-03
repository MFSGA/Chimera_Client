use std::sync::Arc;

use crate::app::dispatcher::statistics_manager::TrackerInfo;

pub struct Tracked(uuid::Uuid, Arc<TrackerInfo>);
