from requests_hardened import Config, Manager

# HTTP server can take some time to connect against for some machines (usually up to 1s).
# It requires a fairly generous timeout without taking too long that the test fails.
SOCKET_TIMEOUT = (4, 0.1)

SSRFFilter = Manager(
    Config(
        default_timeout=SOCKET_TIMEOUT,
        never_redirect=False,
        ip_filter_enable=True,
        ip_filter_allow_loopback_ips=False,
        user_agent_override="user-agent",
    )
)

SSRFFilterAllowLocalHost = SSRFFilter.clone()
SSRFFilterAllowLocalHost.config.ip_filter_allow_loopback_ips = True
