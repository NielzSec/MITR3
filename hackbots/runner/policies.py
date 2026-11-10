"""Validated limits; configuration is not proof of runtime enforcement."""
from collections.abc import Mapping
from dataclasses import asdict, dataclass
import math


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    timeout_s: float = 10.0
    request_timeout_s: float = 5.0
    max_fixture_bytes: int = 1_000_000
    max_events: int = 10_000
    max_total_bytes: int = 16_000_000
    max_read_bytes: int = 65_536
    max_result_bytes: int = 32_768
    max_rejected: int = 3
    max_ipc_messages: int = 20_000
    memory_mb: int = 256
    tasks_max: int = 16
    tmp_bytes: int = 8_000_000

    def __post_init__(self):
        for key, value in asdict(self).items():
            ceiling = _CEILINGS[key]
            if key.endswith('_s'):
                valid = type(value) is int or (type(value) is float and math.isfinite(value))
            else:
                valid = type(value) is int
            if not valid or not 0 < value <= ceiling:
                raise PolicyError('invalid policy limit')
        if self.request_timeout_s > self.timeout_s or self.max_read_bytes > self.max_total_bytes:
            raise PolicyError('inconsistent policy limits')


_CEILINGS = dict(timeout_s=60.0, request_timeout_s=10.0, max_fixture_bytes=1_000_000,
                 max_events=10_000, max_total_bytes=16_000_000, max_read_bytes=65_536,
                 max_result_bytes=32_768, max_rejected=3, max_ipc_messages=20_000,
                 memory_mb=512, tasks_max=64, tmp_bytes=16_000_000)
HARD_MAX = Policy(**_CEILINGS)


def resolve_policy(overrides=None):
    if overrides is None:
        return Policy()
    if not isinstance(overrides, Mapping) or any(key not in _CEILINGS for key in overrides):
        raise PolicyError('unknown policy fields')
    return Policy(**overrides)
