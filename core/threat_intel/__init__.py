"""SecureBridge Threat Intelligence module."""
from .feed_aggregator import ThreatIntelFeed, FeatureDisabledError

__all__ = ["ThreatIntelFeed", "FeatureDisabledError"]
