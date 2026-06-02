"""Custom exceptions for NexScan core."""


class NexScanError(Exception):
    pass


class InvalidPortSpec(NexScanError):
    pass


class InvalidTargetSpec(NexScanError):
    pass


class PrivilegeError(NexScanError):
    pass


class ScanError(NexScanError):
    pass
