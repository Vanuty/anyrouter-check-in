import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from utils.proxy import heal_proxy_connection
from utils.browser import navigate_login_page


def test_heal_proxy_connection_unreachable():
	"""当控制器不可达或关闭时，heal_proxy_connection 静默安全返回，不抛出异常。"""
	result = heal_proxy_connection(controller_url='http://127.0.0.1:59999', timeout=0.1)
	assert isinstance(result, bool)


def test_heal_proxy_connection_success(monkeypatch):
	"""当控制器可达时，正确发起 DELETE connections 与 GET group delay 请求。"""
	called_urls = []

	def fake_urlopen(req, timeout=3.0):
		called_urls.append((req.full_url, req.get_method()))
		m = MagicMock()
		m.__enter__.return_value = m
		m.__exit__.return_value = None
		return m

	monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)

	result = heal_proxy_connection(controller_url='http://127.0.0.1:9090', timeout=1.0)
	assert result is True
	assert ('http://127.0.0.1:9090/connections', 'DELETE') in called_urls
	assert any('/group/CHECKIN/delay' in url and method == 'GET' for url, method in called_urls)


@pytest.mark.asyncio
async def test_navigate_login_page_retries_on_network_error(monkeypatch):
	"""当 page.goto 遭遇网络错误或 ERR_CONNECTION_CLOSED 时，自动捕获并在下一次重试中恢复。"""
	mock_page = MagicMock()
	mock_page.url = 'https://agentrouter.org/login'

	call_count = 0

	async def fake_goto(url, wait_until='load', timeout=60000):
		nonlocal call_count
		call_count += 1
		if call_count == 1:
			raise RuntimeError('net::ERR_CONNECTION_CLOSED at https://agentrouter.org/login')
		return None

	mock_page.goto = AsyncMock(side_effect=fake_goto)
	mock_page.evaluate = AsyncMock(return_value=True)

	monkeypatch.setattr('utils.browser._settle_page', AsyncMock())
	monkeypatch.setattr('utils.browser.dismiss_popups', AsyncMock(return_value=0))
	monkeypatch.setattr('utils.browser._wait_for_login_shell', AsyncMock(return_value=True))
	monkeypatch.setattr('utils.browser.wait_for_site_ready', AsyncMock())
	monkeypatch.setattr('asyncio.sleep', AsyncMock())
	monkeypatch.setattr('utils.proxy.heal_proxy_connection', MagicMock())

	# 应该在第 2 次重试成功返回，不抛出异常
	await navigate_login_page(mock_page, 'https://agentrouter.org/login', 30000)
	assert call_count >= 2


@pytest.mark.asyncio
async def test_navigate_login_page_retries_on_chrome_error(monkeypatch):
	"""当 page 导航掉入 chrome-error:// 时，自动判定为错误并重试。"""
	mock_page = MagicMock()

	call_count = 0

	async def fake_goto(url, wait_until='load', timeout=60000):
		nonlocal call_count
		call_count += 1
		if call_count == 1:
			mock_page.url = 'chrome-error://chromewebdata/'
		else:
			mock_page.url = 'https://agentrouter.org/login'
		return None

	mock_page.goto = AsyncMock(side_effect=fake_goto)
	mock_page.evaluate = AsyncMock(return_value=True)

	monkeypatch.setattr('utils.browser._settle_page', AsyncMock())
	monkeypatch.setattr('utils.browser.dismiss_popups', AsyncMock(return_value=0))
	monkeypatch.setattr('utils.browser._wait_for_login_shell', AsyncMock(return_value=True))
	monkeypatch.setattr('utils.browser.wait_for_site_ready', AsyncMock())
	monkeypatch.setattr('asyncio.sleep', AsyncMock())
	monkeypatch.setattr('utils.proxy.heal_proxy_connection', MagicMock())

	await navigate_login_page(mock_page, 'https://agentrouter.org/login', 30000)
	assert call_count >= 2
