"""AgentRouter OAuth 静默鉴权与签到重登引擎。

AgentRouter 没有独立的签到按钮/接口，额度只在 OAuth 登录/鉴权回调中由服务端自动发放。
本模块通过第三方平台（GitHub / Linux DO）静默换取授权码 code，直连回调接口触发发奖，
彻底规避阿里云 ESA WAF 的 Web 登录页霸下滑块拦截，并将执行耗时从数分钟压缩至秒级。
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from cloakbrowser import launch_async

from utils.browser import prepare_browser_page
from utils.headers import get_browser_headers
from utils.proxy import get_playwright_proxy

logger = logging.getLogger(__name__)

# 官方客户端 ID 默认备用值
DEFAULT_GITHUB_CLIENT_ID = 'Ov23lidtiR4LeVZvVRNL'
DEFAULT_LINUXDO_CLIENT_ID = 'KZUecGfhhDZMVnv8UtEdhOhf9sNOhqVX'

GITHUB_HOST = 'https://github.com'
LINUXDO_HOST = 'https://linux.do'
LINUXDO_CONNECT_HOST = 'https://connect.linux.do'
LINUXDO_CALLBACK_PATH = '/oauth/linuxdo'

CF_WAIT_ROUNDS = 20
CF_WAIT_MS = 2000
GOTO_ATTEMPTS = 3
RATE_LIMIT_ATTEMPTS = 4
RATE_LIMIT_BACKOFF_SECONDS = 10


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
	"""从 302 重定向 Location 中提取授权码 code；跳回登录页说明会话已失效。"""
	if not location or 'code=' not in location:
		return None
	if location.startswith(f'{GITHUB_HOST}/login') or '/login' in location:
		return None
	query = parse_qs(urlparse(location).query)
	codes = query.get('code')
	return codes[0] if codes else None


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
	"""解析形如 'name1=val1; name2=val2' 或单值形式，保留值原样。"""
	pairs: dict[str, str] = {}
	if not cookie_str:
		return pairs
	text = cookie_str.strip()
	if '=' not in text:
		# 单一 token 默认归入 _t
		return {'_t': text}
	for part in text.split(';'):
		name, sep, val = part.strip().partition('=')
		if sep and name:
			pairs[name.strip()] = val.strip()
	return pairs


async def _goto_with_retry(page, url: str) -> None:
	for attempt in range(GOTO_ATTEMPTS):
		try:
			await page.goto(url, wait_until='domcontentloaded', timeout=60000)
			return
		except Exception:
			if attempt == GOTO_ATTEMPTS - 1:
				raise
			await page.wait_for_timeout(3000)


async def _wait_out_challenge(page) -> None:
	"""等待 Cloudflare 挑战页（'请稍候…' 或 'Just a moment'）跳转。"""
	for _ in range(CF_WAIT_ROUNDS):
		try:
			title = await page.title()
		except Exception:
			title = ''
		if title and '请稍候' not in title and 'Just a moment' not in title:
			return
		await page.wait_for_timeout(CF_WAIT_MS)


class AgentRouterOAuthClient:
	"""AgentRouter OAuth 静默鉴权客户端"""

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

	def _get_json_with_retry(self, client: httpx.Client, url: str, *, params: dict | None = None) -> dict:
		"""请求 JSON 并处理 AgentRouter 429 限流指数退避。"""
		headers = get_browser_headers(domain=self.domain)
		for attempt in range(RATE_LIMIT_ATTEMPTS):
			resp = client.get(url, params=params, headers=headers)
			if resp.status_code != 429:
				resp.raise_for_status()
				try:
					return resp.json()
				except Exception as e:
					raise RuntimeError(f'响应非有效 JSON (HTTP {resp.status_code}): {resp.text[:120]}') from e
			if attempt == RATE_LIMIT_ATTEMPTS - 1:
				raise RuntimeError(f'AgentRouter 限流 (429)，重试多次后仍未恢复: {url}')
			backoff = RATE_LIMIT_BACKOFF_SECONDS * (attempt + 1)
			print(f'[WARN] AgentRouter 429 限流，等待 {backoff} 秒后重试...')
			time.sleep(backoff)
		return {}

	def fetch_oauth_state(self, client: httpx.Client) -> str:
		"""请求平台获取签名 OAuth state。

		带上旧 session 请求 state 会被服务端判定为 'state is empty or not same'，
		因此在此步骤强制使用干净的临时 Cookie 会话。
		"""
		# 尝试从 /api/status 动态刷新客户端 ID
		try:
			status_url = f'{self.domain}/api/status'
			status_body = self._get_json_with_retry(client, status_url)
			data = status_body.get('data') or {}
			if data.get('github_client_id'):
				self.github_client_id = data['github_client_id']
			if data.get('linuxdo_client_id'):
				self.linuxdo_client_id = data['linuxdo_client_id']
		except Exception as e:
			logger.debug(f'动态获取 OAuth client_id 失败，使用内置默认 ID: {e}')

		# 临时保存已有 cookies，用干净上下文获取 state
		saved_session = client.cookies.get('session')
		if 'session' in client.cookies:
			del client.cookies['session']
		try:
			url = f'{self.domain}/api/oauth/state'
			params = {'mode': 'login'}
			try:
				body = self._get_json_with_retry(client, url, params=params)
			except Exception:
				# 备用源站镜像降级
				self.domain = self.backup_domain
				url = f'{self.domain}/api/oauth/state'
				body = self._get_json_with_retry(client, url, params=params)

			if not body.get('success') or not body.get('data'):
				raise RuntimeError(f'获取 OAuth state 失败: {body.get("message")}')
			return str(body['data'])
		finally:
			if saved_session:
				client.cookies.set('session', saved_session)

	def authorize_github(
		self,
		github_session_token: str,
		state: str,
		*,
		proxy_url: str | None = None,
	) -> str:
		"""通过 GitHub 携带 user_session 申请授权并静默提取 code（耗时 <1 秒）。"""
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

			if 'code=' in resp.text:
				code_match = re.search(r'code=([a-zA-Z0-9_-]+)', resp.text)
				if code_match:
					return code_match.group(1)

			if resp.status_code in (301, 302, 303):
				if location.startswith(f'{GITHUB_HOST}/login'):
					raise RuntimeError('GitHub 会话已失效（跳转至登录页），请更新 github_session')
				raise RuntimeError(f'GitHub 未返回授权码，重定向地址: {location[:150]}')

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
			sample_text = re.sub(r'\s+', ' ', resp.text[:400])
			raise RuntimeError(f'未能从 GitHub 获取授权码 (HTTP {resp.status_code}, title: {title}): {sample_text}')

	async def authorize_linuxdo(
		self,
		linuxdo_session_token: str,
		state: str,
		*,
		use_proxy: bool = False,
	) -> str:
		"""通过 CloakBrowser 穿透 Cloudflare 质询并靶向截获 Linux DO 授权码。"""
		cookies = parse_cookie_string(linuxdo_session_token)
		if not cookies:
			raise RuntimeError('linuxdo_session 格式无效，请提供 _t 或 _forum_session')

		launch_kwargs: dict[str, Any] = {'headless': True}
		proxy = get_playwright_proxy(use_proxy=use_proxy)
		if proxy:
			launch_kwargs['proxy'] = proxy

		browser = await launch_async(**launch_kwargs)
		captured: list[str] = []

		async def capture(route) -> None:
			c = extract_code_from_location(route.request.url)
			if c:
				captured.append(c)
				await route.abort()
			else:
				await route.continue_()

		try:
			context = await browser.new_context()
			# 种到父域 .linux.do
			await context.add_cookies([
				{
					'name': name,
					'value': value,
					'domain': '.linux.do',
					'path': '/',
					'secure': True,
					'httpOnly': True,
				}
				for name, value in cookies.items()
			])

			page = await context.new_page()
			await page.route(f'**{LINUXDO_CALLBACK_PATH}**', capture)
			await prepare_browser_page(page)

			# 先访问 linux.do 过 Cloudflare 质询拿 cf_clearance
			await _goto_with_retry(page, f'{LINUXDO_HOST}/')
			await _wait_out_challenge(page)

			# 跳转授权申请
			params = {
				'response_type': 'code',
				'client_id': self.linuxdo_client_id,
				'state': state,
			}
			await _goto_with_retry(page, f'{LINUXDO_CONNECT_HOST}/oauth2/authorize?{urlencode(params)}')

			approved = False
			for _ in range(CF_WAIT_ROUNDS):
				if captured:
					return captured[0]
				if not approved:
					approve = page.locator('a[href*="/oauth2/approve/"]')
					if await approve.count():
						await approve.first.click()
						approved = True
				await page.wait_for_timeout(CF_WAIT_MS)
				if page.url.startswith(f'{LINUXDO_HOST}/login'):
					raise RuntimeError('Linux DO 会话已失效（被跳转至登录页），请更新 linuxdo_session')

			if captured:
				return captured[0]
			raise RuntimeError(f'Linux DO 未能获取授权码（停在 {page.url[:60]}）')
		finally:
			await browser.close()

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

		body = self._get_json_with_retry(client, url, params=params)
		if not body.get('success'):
			return False, {}, False, body.get('message', 'OAuth 回调登录失败')

		data = body.get('data') or {}
		checked_in = bool(data.get('checked_in'))
		return True, data, checked_in, body.get('message', '')
