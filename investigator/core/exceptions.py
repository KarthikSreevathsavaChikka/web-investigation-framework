"""Framework-specific exceptions."""


class InvestigationFrameworkError(Exception):
    """Base class for framework errors."""


class PipelineConfigurationError(InvestigationFrameworkError):
    """Raised when a pipeline definition is invalid."""


class PipelineExecutionError(InvestigationFrameworkError):
    """Raised when a pipeline cannot be executed."""
