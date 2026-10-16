"""AgentRouter OAuth 静默鉴权与签到重登引擎"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

import httpx

from utils.headers import get_browser_headers

logger = logging.getLogger(__name__)

# 官方客户端 ID
DEFAULT_GITHUB_CLIENT_ID = 'Ov23lidtiR4LeVZvVRNL'
DEFAULT_LINUXDO_CLIENT_ID = 'KZUecGfhhDZMVnv8UtEdhOhf9sNOhqVX'

GITHUB_HOST = 'https://github.com'
LINUXDO_CONNECT_HOST = 'https://connect.linux.do'


def build_github_cookies(session_value: str) -> dict[str, str]:
	"""根据 GitHub user_session 构造标准会话 Cookie。"""
	val = (session_value or '').strip()
	cookies: dict[str, str] = {}
	if val:
		cookies['user_session'] = val
		cookies['logged_in'] = 'yes'
		cookies['__Host-user_session_same_site'] = val
	return cookies


def extract_code_from_location(location: str | None) -> str | None:
	"""从 302 重定向 Location 中提取授权码 code。"""
	if not location or 'code=' not in location:
		return None
	if location.startswith(f'{GITHUB_HOST}/login') or '/login' in location:
		return None
	query = parse_qs(urlparse(location).query)
	codes = query.get('code')
	return codes[0] if codes else None


class AgentRouterOAuthClient:
	"""AgentRouter OAuth 静默登录客户端"""

	def __init__(
		self,
		domain: str = 'https://agentrouter.org',
		*,
		backup_domain: str = 'https://ps.air-outer.com',
		github_client_id: str = DEFAULT_GITHUB_CLIENT_ID,
		linuxdo_client_id: str = DEFAULT_LINUXDO_CLIENT_ID,
	) -> None:
		self.domain = domain.rstrip('/')
		self.backup_domain = backup_domain.rstrip('/')
		self.github_client_id = github_client_id
		self.linuxdo_client_id = linuxdo_client_id

	def fetch_oauth_state(self, client: httpx.Client) -> str:
		"""请求平台获取签名 OAuth state。"""
		url = f'{self.domain}/api/oauth/state'
		headers = get_browser_headers(domain=self.domain)
		resp = client.get(url, headers=headers)
		if resp.status_code != 200:
			# 备用域名降级重试
			fallback_url = f'{self.backup_domain}/api/oauth/state'
			resp = client.get(fallback_url, headers=get_browser_headers(domain=self.backup_domain))
			if resp.status_code == 200:
				self.domain = self.backup_domain

		resp.raise_for_status()
		try:
			body = resp.json()
		except Exception as e:
			raise RuntimeError(f'获取 OAuth state 响应非 JSON (HTTP {resp.status_code}): {resp.text[:120]}')
		if not body.get('success') or not body.get('data'):
			raise RuntimeError(f'获取 OAuth state 失败: {body.get("message")}')
		return str(body['data'])

	def authorize_github(
		self,
		github_session_token: str,
		state: str,
		*,
		proxy_url: str | None = None,
	) -> str:
		"""通过 GitHub 携带 user_session 申请授权并静默提取 code。"""
		client_kwargs: dict[str, Any] = {'follow_redirects': False, 'timeout': 30.0}
		if proxy_url:
			client_kwargs['proxy'] = proxy_url

		cookies = build_github_cookies(github_session_token)
		headers = get_browser_headers(domain=GITHUB_HOST)
		authorize_url = f'{GITHUB_HOST}/login/oauth/authorize'
		params = {
			'client_id': self.github_client_id,
			'state': state,
			'scope': 'user:email',
		}

		with httpx.Client(**client_kwargs) as client:
			resp = client.get(authorize_url, params=params, cookies=cookies, headers=headers)
			location = resp.headers.get('location') or ''
			code = extract_code_from_location(location)
			if code:
				return code

			# 检查页面内容中的跳转链接、meta refresh 或页面内嵌入的 code
			if 'code=' in resp.text:
				code_match = re.search(r'code=([a-zA-Z0-9_-]+)', resp.text)
				if code_match:
					return code_match.group(1)

			if resp.status_code in (301, 302, 303):
				if location.startswith(f'{GITHUB_HOST}/login'):
					raise RuntimeError('GitHub 登录态无效或已过期，请更新 github_session')
				raise RuntimeError(f'GitHub 未返回授权码，跳转地址: {location[:150]}')
			# 首次授权表单处理
			if resp.status_code == 200 and 'action=' in resp.text:
				action_match = re.search(r'<form[^>]+action="([^"]+)"', resp.text)
				if action_match:
					form_action = action_match.group(1)
					if not form_action.startswith('http'):
						form_action = GITHUB_HOST + form_action
					payload: dict[str, str] = {'authorize': '1'}
					for tag in re.findall(r'<input[^>]*>', resp.text):
						if 'type="hidden"' not in tag:
							continue
						n = re.search(r'name="([^"]+)"', tag)
						v = re.search(r'value="([^"]*)"', tag)
						if n:
							payload[n.group(1)] = v.group(1) if v else ''

					post_resp = client.post(form_action, data=payload, cookies=cookies, headers=headers)
					post_loc = post_resp.headers.get('location') or ''
					code = extract_code_from_location(post_loc)
					if code:
						return code

			title_m = re.search(r'<title>(.*?)</title>', resp.text, re.I)
			title = title_m.group(1) if title_m else 'No title'
			forms = re.findall(r'<form[^>]*>', resp.text, re.I)
			sample_text = re.sub(r'\s+', ' ', resp.text[:1000])
			raise RuntimeError(f'未能从 GitHub 获取授权码 (HTTP {resp.status_code}, title: {title}, forms: {forms}): {sample_text}')
	def authorize_linuxdo(
		self,
		linuxdo_session_token: str,
		state: str,
		*,
		proxy_url: str | None = None,
	) -> str:
		"""通过 LinuxDo 携带会话申请授权并静默提取 code。"""
		client_kwargs: dict[str, Any] = {'follow_redirects': False, 'timeout': 30.0}
		if proxy_url:
			client_kwargs['proxy'] = proxy_url

		cookies = {'_forum_session': linuxdo_session_token}
		headers = get_browser_headers(domain=LINUXDO_CONNECT_HOST)
		authorize_url = f'{LINUXDO_CONNECT_HOST}/oauth/authorize'
		params = {
			'client_id': self.linuxdo_client_id,
			'state': state,
			'response_type': 'code',
		}

		with httpx.Client(**client_kwargs) as client:
			resp = client.get(authorize_url, params=params, cookies=cookies, headers=headers)
			location = resp.headers.get('location') or ''
			code = extract_code_from_location(location)
			if code:
				return code
			sample_text = re.sub(r'\s+', ' ', resp.text[:300])
			raise RuntimeError(f'未能从 LinuxDo 获取授权码 (HTTP {resp.status_code}, url: {resp.url}, loc: {location}): {sample_text}')

	def callback_login(
		self,
		client: httpx.Client,
		*,
		provider: str,
		code: str,
		state: str,
	) -> tuple[bool, dict[str, Any], bool, str]:
		"""携带授权码触发 AgentRouter 登录回调以激活签到发奖。"""
		url = f'{self.domain}/api/oauth/{provider}'
		params = {'code': code, 'state': state, 'mode': 'login'}
		headers = get_browser_headers(domain=self.domain)

		resp = client.get(url, params=params, headers=headers)
		if resp.status_code != 200:
			return False, {}, False, f'OAuth 回调失败 (HTTP {resp.status_code})'

		try:
			body = resp.json()
		except Exception as e:
			return False, {}, False, f'解析回调响应失败: {e}'

		if not body.get('success'):
			return False, {}, False, body.get('message', 'OAuth 回调登录失败')

		data = body.get('data') or {}
		checked_in = bool(data.get('checked_in'))
		return True, data, checked_in, body.get('message', '')
