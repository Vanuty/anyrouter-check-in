"""代理配置：读取环境变量并供浏览器 / HTTP 客户端使用。"""

from __future__ import annotations

import os
from urllib.parse import unquote, urlsplit, urlunsplit


def get_proxy_server(*, use_proxy: bool = True) -> str | None:
	"""按平台配置读取 CHECKIN_PROXY_URL；use_proxy=False 时不返回代理地址。"""
	if not use_proxy:
		return None
	server = os.getenv('CHECKIN_PROXY_URL', '').strip()
	return server or None


def get_playwright_proxy(*, use_proxy: bool = True) -> dict[str, str] | None:
	server = get_proxy_server(use_proxy=use_proxy)
	if not server:
		return None
	parsed = urlsplit(server)
	if not parsed.username:
		return {'server': server}
	host = parsed.hostname or ''
	if ':' in host and not host.startswith('['):
		host = f'[{host}]'
	if parsed.port:
		host = f'{host}:{parsed.port}'
	return {
		'server': urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment)),
		'username': unquote(parsed.username),
		'password': unquote(parsed.password or ''),
	}


def heal_proxy_connection(
	controller_url: str = 'http://127.0.0.1:9090',
	timeout: float = 3.0,
) -> bool:
	"""当遭遇 TCP 瞬断、ERR_CONNECTION_CLOSED 时，通过 Mihomo 外部控制接口清理僵死连接并触发节点重测。"""
	try:
		import urllib.request

		ctrl_base = controller_url.rstrip('/')

		# 1. 彻底清空僵死 TCP 连接池（防止 Chromium 复用已断开的 Socket）
		del_req = urllib.request.Request(f'{ctrl_base}/connections', method='DELETE')
		try:
			with urllib.request.urlopen(del_req, timeout=timeout):
				pass
		except Exception:
			pass

		# 2. 并发触发所有代理组测速自愈，促使 Mihomo 剔除超时节点并切换健康节点
		for group in ['CHECKIN_SG', 'CHECKIN_ALL', 'CHECKIN']:
			try:
				url = f'{ctrl_base}/group/{group}/delay?timeout=3000'
				with urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=timeout):
					pass
			except Exception:
				pass
		return True
	except Exception:
		return False

