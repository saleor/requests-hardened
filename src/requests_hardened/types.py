from typing import Union, Tuple

T_TIMEOUT = Union[int, float]
T_TIMEOUT_TUPLE = Tuple[T_TIMEOUT, T_TIMEOUT]
T_REQUESTS_TIMEOUT_ARG = Union[T_TIMEOUT, Tuple[T_TIMEOUT, T_TIMEOUT]]
