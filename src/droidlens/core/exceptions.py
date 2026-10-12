class DroidLensError(Exception):
    """Base class for all pipeline errors."""


class IngestError(DroidLensError):
    """APK could not be parsed/analyzed."""


class IngestTimeout(IngestError):
    """Androguard analysis exceeded the configured timeout."""


class IngestCrash(IngestError):
    """Child analysis process died (OOM, segfault, malformed dex)."""

