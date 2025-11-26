# -*- coding: gbk -*-

"""
__init__.py for src package
"""
from .deduplication import deduplicate_dataset, FunctionDeduplicator
from .labeling_onefunc import apply_onefunc_labeling, OneFuncLabeler
from .labeling_nvdcheck import apply_nvdcheck_labeling, NVDCheckLabeler
from .temporal_split import temporal_split, TemporalSplitter
from .paired_functions import build_paired_dataset, PairedFunctionBuilder
from .data_loader import DataLoader, load_nvd_data
from .utils import (
    print_dataset_statistics,
    validate_dataset,
    print_validation_results,
    visualize_dataset_distribution
)

__all__ = [
    # Deduplication
    'deduplicate_dataset',
    'FunctionDeduplicator',
    
    # Labeling
    'apply_onefunc_labeling',
    'OneFuncLabeler',
    'apply_nvdcheck_labeling',
    'NVDCheckLabeler',
    
    # Splitting
    'temporal_split',
    'TemporalSplitter',
    
    # Paired functions
    'build_paired_dataset',
    'PairedFunctionBuilder',
    
    # Data loading
    'DataLoader',
    'load_nvd_data',
    
    # Utils
    'print_dataset_statistics',
    'validate_dataset',
    'print_validation_results',
    'visualize_dataset_distribution',
]
