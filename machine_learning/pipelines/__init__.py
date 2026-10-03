"""Machine learning pipelines package for data loading, inspection, feature engineering, and preprocessing."""


def __getattr__(name):
    if name == "DatasetLoader":
        from machine_learning.pipelines.dataset_loader import DatasetLoader
        return DatasetLoader
    elif name == "DatasetInspector":
        from machine_learning.pipelines.dataset_inspector import DatasetInspector
        return DatasetInspector
    elif name == "NetworkFeatureEngineer":
        from machine_learning.pipelines.feature_engineering import NetworkFeatureEngineer
        return NetworkFeatureEngineer
    elif name == "NetworkDataPreprocessor":
        from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor
        return NetworkDataPreprocessor
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "DatasetLoader",
    "DatasetInspector",
    "NetworkFeatureEngineer",
    "NetworkDataPreprocessor",
]
