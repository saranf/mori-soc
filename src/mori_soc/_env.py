"""환경변수 파싱 공용 헬퍼 (공통화 C10).

`_env_flag` 가 pollers/base 와 integrations/zabbix_writeback 에 중복 정의돼 있던 것을
한 곳으로 모은다. bool 플래그 해석 규칙(1/true/yes/on)을 단일화.
"""
from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def env_flag(name: str, default: bool = False) -> bool:
    """환경변수를 bool 로 해석. 미설정 시 default. (1/true/yes/on → True)"""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUTHY
