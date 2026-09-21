// src/worker.js

const subLinks = [
	'https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/trojan.txt',
	'https://raw.githubusercontent.com/10ium/V2Hub3/main/Split/Normal/trojan',
	'https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/Iran.txt',
	'https://raw.githubusercontent.com/10ium/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt',
	'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/trojan.txt',
	'https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt',
	'https://raw.githubusercontent.com/plsn1337/white-vless/refs/heads/main/filtered_vless_keys.txt',
	'https://raw.githubusercontent.com/10ium/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt',
	'https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt',
];

const SOURCE_TIMEOUT = 8000;
const CONFIG_TIMEOUT = 4000;

// Checks run concurrently (I/O bound, so this can be reasonably high).
const CHECK_CONCURRENCY = 24;

const MAX_CHECK_CANDIDATES = 40;

const HOME_HOSTNAME = 'node-garden.eindev.ir';
const HOME_ORIGIN = `https://${HOME_HOSTNAME}`;

const SUBSCRIPTION_HOSTNAME = 'trojan.eghafari-5000.workers.dev';
const SUBSCRIPTION_ORIGIN = `https://${SUBSCRIPTION_HOSTNAME}`;

const CLEAN_IP_URL = 'https://api.hostmonit.com/get_optimization_ip';
const CLEAN_IP_PAYLOAD = {
	key: 'o1zrmHAF',
	type: 'v4',
};
const CLEAN_IP_HEADERS = {
	'Content-Type': 'application/json',
};

const CLEAN_IP_TIMEOUT = 5000;

let cleanIpCache = {
	ips: [],
	expiresAt: 0,
};

/* -------------------------------------------------------------------------- */
/* Worker                                                                     */
/* -------------------------------------------------------------------------- */

export default {
	async fetch(request) {
		const url = new URL(request.url);

		if (url.pathname === '/') {
			if (url.hostname !== HOME_HOSTNAME) {
				return Response.redirect(`${HOME_ORIGIN}/`, 302);
			}

			return new Response(renderHomePage(), {
				headers: {
					'content-type': 'text/html; charset=UTF-8',
					'cache-control': 'no-store',
				},
			});
		}

		if (url.pathname === '/fa') {
			if (url.hostname !== HOME_HOSTNAME) {
				return Response.redirect(`${HOME_ORIGIN}/fa`, 302);
			}

			return new Response(renderHomePageFa(), {
				headers: {
					'content-type': 'text/html; charset=UTF-8',
					'cache-control': 'no-store',
				},
			});
		}

		// Source status API
		if (url.pathname === '/api/sub-links') {
			return handleSourceStatus();
		}

		// Subscription
		if (url.pathname === '/sub' || url.pathname.startsWith('/sub/')) {
			return handleSubscription(url, request);
		}

		// Original proxy behavior
		const parts = url.pathname.replace(/^\/+/, '').split('/');
		const address = parts.shift();

		if (!address) {
			return new Response('Not Found', { status: 404 });
		}

		url.hostname = address;
		url.protocol = 'https:';
		url.pathname = '/' + parts.join('/');

		return fetch(new Request(url, request));
	},
};

function randomItem(array) {
	return array[Math.floor(Math.random() * array.length)];
}

async function getRandomCleanIp() {
	const now = Date.now();

	// Reuse the IP list for 5 minutes,
	// but choose a different random IP on every subscription request.
	if (cleanIpCache.expiresAt > now && cleanIpCache.ips.length > 0) {
		return randomItem(cleanIpCache.ips);
	}

	try {
		const controller = new AbortController();

		const timeout = setTimeout(() => {
			controller.abort();
		}, CLEAN_IP_TIMEOUT);

		try {
			const response = await fetch(CLEAN_IP_URL, {
				method: 'POST',
				headers: {
					...CLEAN_IP_HEADERS,
					'cache-control': 'no-cache',
				},
				body: JSON.stringify(CLEAN_IP_PAYLOAD),
				signal: controller.signal,
			});

			if (!response.ok) {
				return null;
			}

			const data = await response.json();

			const ips = [
				...new Set(
					(Array.isArray(data?.info) ? data.info : [])
						.map((item) => item?.ip)
						.filter(isIp),
				),
			];

			if (ips.length === 0) {
				return null;
			}

			cleanIpCache = {
				ips,
				expiresAt: now + 5 * 60 * 1000,
			};

			return randomItem(ips);
		} finally {
			clearTimeout(timeout);
		}
	} catch {
		return null;
	}
}

/* -------------------------------------------------------------------------- */
/* Subscription                                                               */
/* -------------------------------------------------------------------------- */

function wantsHtmlLoadingPage(request, url) {
	// Explicit opt-outs: proxy clients or anyone who wants the raw list.
	if (url.searchParams.get('raw') === '1') return false;
	if (url.searchParams.get('format') === 'raw') return false;

	const accept = request.headers.get('accept') || '';
	return accept.includes('text/html');
}

function buildRawSubUrl(url) {
	const rawUrl = new URL(url.toString());
	rawUrl.searchParams.set('raw', '1');
	return rawUrl.pathname + rawUrl.search;
}

function buildCanonicalSubUrl(url) {
	const canonical = new URL(url.pathname + url.search, SUBSCRIPTION_ORIGIN);
	canonical.searchParams.delete('raw');
	return canonical.toString();
}

async function handleSubscription(url, request) {
	if (request && wantsHtmlLoadingPage(request, url)) {
		return new Response(renderSubLoadingPage(buildRawSubUrl(url), buildCanonicalSubUrl(url)), {
			headers: {
				'content-type': 'text/html; charset=UTF-8',
				'cache-control': 'no-store',
			},
		});
	}

	const pathParts = url.pathname.split('/').filter(Boolean);

	const realAddress = pathParts[1] || '';

	// Configs' host/sni always point at the dedicated subscription domain,
	// not whichever domain this request happened to arrive on.
	const workerHostname = SUBSCRIPTION_HOSTNAME;

	// Use a random Cloudflare clean IP for the client-facing address.
	const cleanIp = await getRandomCleanIp();

	const outputAddress = cleanIp || realAddress || SUBSCRIPTION_HOSTNAME;

	const checkEnabled = url.searchParams.get('check') !== '0';
	const n = parsePositiveInt(url.searchParams.get('n'));

	const candidates = [];

	const seen = {
		vmess: new Set(),
		vless: new Set(),
		trojan: new Set(),
	};

	for (let sourceIndex = 0; sourceIndex < subLinks.length; sourceIndex++) {
		const source = subLinks[sourceIndex];

		try {
			const response = await fetchTimeout(
				source,
				{
					headers: {
						'cache-control': 'no-cache',
					},
				},
				SOURCE_TIMEOUT,
			);

			if (!response.ok) continue;

			let text = await response.text();
			text = decodeBase64IfNeeded(text);

			const lines = text.split(/\r?\n/);

			for (const raw of lines) {
				const line = raw.trim();

				if (!line) continue;

				try {
					/* ------------------------------- VMESS ------------------------------- */

					if (line.startsWith('vmess://')) {
						const parsed = parseVmess(line);

						if (!parsed) continue;

						if (!parsed.sni || isIp(parsed.sni) || parsed.net !== 'ws' || parsed.port !== 443) {
							continue;
						}

						if (shouldSkipHost(parsed.sni)) {
							continue;
						}

						const upstreamPath = normalizePath(parsed.path);
						const dedupeKey = `${parsed.sni}|${upstreamPath}`;

						if (seen.vmess.has(dedupeKey)) {
							continue;
						}

						seen.vmess.add(dedupeKey);

						const workerPath = `/${parsed.sni}${upstreamPath}`;

						const config = {
							v: '2',
							ps: makeNodeName('vmess', parsed.sni, upstreamPath, sourceIndex),
							add: outputAddress,
							port: 443,
							id: parsed.id,
							net: 'ws',
							type: 'ws',
							host: workerHostname,
							path: workerPath,
							tls: parsed.tls || 'tls',
							sni: workerHostname,
							aid: '0',
							scy: 'auto',
							fp: 'chrome',
							alpn: 'http/1.1',
						};

						candidates.push({
							protocol: 'vmess',
							sni: parsed.sni,
							path: upstreamPath,
							sourceIndex,
							value: 'vmess://' + btoa(JSON.stringify(config)),
						});

						continue;
					}

					/* ------------------------------- VLESS ------------------------------- */

					if (line.startsWith('vless://')) {
						const parsed = parseVless(line);

						if (!parsed) continue;

						if (!parsed.sni || isIp(parsed.sni) || parsed.security !== 'tls' || parsed.port !== 443 || parsed.type !== 'ws') {
							continue;
						}

						if (shouldSkipHost(parsed.sni)) {
							continue;
						}

						const upstreamPath = normalizePath(parsed.path);
						const dedupeKey = `${parsed.sni}|${upstreamPath}`;

						if (seen.vless.has(dedupeKey)) {
							continue;
						}

						seen.vless.add(dedupeKey);

						const workerPath = `/${parsed.sni}${upstreamPath}`;
						const name = makeNodeName('vless', parsed.sni, upstreamPath, sourceIndex);

						const config =
							`vless://${encodeURIComponent(parsed.uuid)}` +
							`@${outputAddress}:443` +
							`?encryption=none` +
							`&security=tls` +
							`&sni=${encodeURIComponent(workerHostname)}` +
							`&alpn=http%2F1.1` +
							`&fp=chrome` +
							`&allowInsecure=1` +
							`&type=ws` +
							`&host=${encodeURIComponent(workerHostname)}` +
							`&path=${encodeURIComponent(workerPath)}` +
							`#${encodeURIComponent(name)}`;

						candidates.push({
							protocol: 'vless',
							sni: parsed.sni,
							path: upstreamPath,
							sourceIndex,
							value: config,
						});

						continue;
					}

					/* ------------------------------- TROJAN ------------------------------ */

					if (line.startsWith('trojan://')) {
						const parsed = parseTrojan(line);

						if (!parsed) continue;

						if (!parsed.sni || isIp(parsed.sni) || parsed.security !== 'tls' || parsed.port !== 443 || parsed.type !== 'ws') {
							continue;
						}

						if (shouldSkipHost(parsed.sni)) {
							continue;
						}

						const upstreamPath = normalizePath(parsed.path);
						const dedupeKey = `${parsed.sni}|${upstreamPath}`;

						if (seen.trojan.has(dedupeKey)) {
							continue;
						}

						seen.trojan.add(dedupeKey);

						const workerPath = `/${parsed.sni}${upstreamPath}`;
						const name = makeNodeName('trojan', parsed.sni, upstreamPath, sourceIndex);

						const config =
							`trojan://${encodeURIComponent(parsed.password)}` +
							`@${outputAddress}:443` +
							`?security=tls` +
							`&sni=${encodeURIComponent(workerHostname)}` +
							`&alpn=http%2F1.1` +
							`&fp=chrome` +
							`&allowInsecure=1` +
							`&type=ws` +
							`&host=${encodeURIComponent(workerHostname)}` +
							`&path=${encodeURIComponent(workerPath)}` +
							`#${encodeURIComponent(name)}`;

						candidates.push({
							protocol: 'trojan',
							sni: parsed.sni,
							path: upstreamPath,
							sourceIndex,
							value: config,
						});
					}
				} catch {
					// Ignore malformed individual configs.
				}
			}
		} catch {
			// Ignore failed subscription sources.
		}
	}

	let working = candidates;
	let checkedCount = 0;
	let skippedForBudget = 0;

	if (checkEnabled && candidates.length > 0) {
		const toCheck = selectCandidatesForCheck(candidates, MAX_CHECK_CANDIDATES);

		checkedCount = toCheck.length;
		skippedForBudget = candidates.length - toCheck.length;

		working = await filterWorking(toCheck);
	}

	let result = working.map((item) => item.value);

	// ?n=10
	if (n) {
		result = randomItems(result, Math.min(n, result.length));
	}

	const body = result.length ? result.join('\n') + '\n' : '';

	return new Response(body, {
		headers: {
			'content-type': 'text/plain; charset=UTF-8',
			'cache-control': checkEnabled ? 'no-store' : 'public, max-age=60',
			'x-total-configs': String(candidates.length),
			'x-checked-configs': String(checkedCount),
			'x-skipped-for-subrequest-budget': String(skippedForBudget),
			'x-working-configs': String(result.length),
		},
	});
}

/* -------------------------------------------------------------------------- */
/* Live config checking                                                       */
/* -------------------------------------------------------------------------- */

/**
 * When there are more candidates than we can afford to check within the
 * Worker's subrequest budget, pick a fair cross-section instead of just
 * taking the first N (which would silently favor whichever source happens
 * to come first in `subLinks`). Round-robins across sources so every
 * source gets a shot at contributing working nodes.
 */
function selectCandidatesForCheck(candidates, max) {
	if (candidates.length <= max) {
		return candidates;
	}

	const groups = new Map();

	for (const candidate of candidates) {
		const list = groups.get(candidate.sourceIndex) || [];
		list.push(candidate);
		groups.set(candidate.sourceIndex, list);
	}

	const groupArrays = [...groups.values()];
	const selected = [];

	let index = 0;

	while (selected.length < max) {
		let addedAny = false;

		for (const group of groupArrays) {
			if (index < group.length) {
				selected.push(group[index]);
				addedAny = true;

				if (selected.length >= max) {
					break;
				}
			}
		}

		if (!addedAny) {
			break;
		}

		index++;
	}

	return selected;
}

async function filterWorking(candidates) {
	const result = new Array(candidates.length).fill(false);

	let cursor = 0;

	async function runner() {
		while (true) {
			const index = cursor++;

			if (index >= candidates.length) {
				return;
			}

			result[index] = await checkConfig(candidates[index]);
		}
	}

	const count = Math.min(CHECK_CONCURRENCY, candidates.length);

	await Promise.all(Array.from({ length: count }, () => runner()));

	return candidates.filter((_, index) => result[index]);
}

async function checkConfig(candidate) {
	if (!candidate?.sni) {
		return false;
	}

	const target = `https://${candidate.sni}` + normalizePath(candidate.path);

	try {
		/*
		 * Cloudflare Worker outbound WebSocket handshake.
		 *
		 * This confirms:
		 *   DNS works
		 *   TLS works
		 *   remote server accepts WebSocket upgrade
		 *
		 * It does NOT authenticate VLESS/Trojan credentials.
		 */
		const response = await fetchTimeout(
			target,
			{
				headers: {
					Upgrade: 'websocket',
					Connection: 'Upgrade',
				},
			},
			CONFIG_TIMEOUT,
		);

		if (response.status !== 101 || !response.webSocket) {
			return false;
		}

		try {
			response.webSocket.accept();
			response.webSocket.close(1000, 'health-check');
		} catch {
			// Handshake was already successful.
		}

		return true;
	} catch {
		return false;
	}
}

/* -------------------------------------------------------------------------- */
/* Source status                                                              */
/* -------------------------------------------------------------------------- */

async function handleSourceStatus() {
	const results = await Promise.all(subLinks.map(checkSubLink));

	return jsonResponse({
		checkedAt: new Date().toISOString(),
		results,
	});
}

async function checkSubLink(source) {
	const started = Date.now();

	try {
		const response = await fetchTimeout(
			source,
			{
				headers: {
					'cache-control': 'no-cache',
				},
			},
			SOURCE_TIMEOUT,
		);

		const result = {
			url: source,
			ok: response.ok,
			status: response.status,
			latencyMs: Date.now() - started,
			error: null,
		};

		try {
			await response.body?.cancel();
		} catch {}

		return result;
	} catch (error) {
		return {
			url: source,
			ok: false,
			status: null,
			latencyMs: Date.now() - started,
			error: error instanceof Error ? error.message : 'request failed',
		};
	}
}

/* -------------------------------------------------------------------------- */
/* Cute names                                                                 */
/* -------------------------------------------------------------------------- */

const ANIMALS = ['🐱', '🦊', '🐼', '🐨', '🐸', '🐙', '🐰', '🦋', '🐹', '🐥', '🦄', '🐳'];

const WORDS = ['Mochi', 'Nova', 'Pixel', 'Cloud', 'Moon', 'Peach', 'Jelly', 'Velvet', 'Mint', 'Dream', 'Bubble', 'Cozy'];

const SPARKLES = ['✨', '🌙', '☁️', '💫', '🌸', '🍀', '🫧', '⭐', '🍑', '🪐', '💜', '🌿'];

const FLAGS = {
	ir: '🇮🇷',
	us: '🇺🇸',
	de: '🇩🇪',
	nl: '🇳🇱',
	fr: '🇫🇷',
	gb: '🇬🇧',
	uk: '🇬🇧',
	fi: '🇫🇮',
	se: '🇸🇪',
	no: '🇳🇴',
	dk: '🇩🇰',
	tr: '🇹🇷',
	ae: '🇦🇪',
	sg: '🇸🇬',
	jp: '🇯🇵',
	kr: '🇰🇷',
	ca: '🇨🇦',
	ru: '🇷🇺',
	ch: '🇨🇭',
	it: '🇮🇹',
	es: '🇪🇸',
	au: '🇦🇺',
	pl: '🇵🇱',
	in: '🇮🇳',
	hk: '🇭🇰',
	tw: '🇹🇼',
	br: '🇧🇷',
};

function makeNodeName(protocol, host, path, sourceIndex) {
	const seed = `${protocol}|${host}|${path}|${sourceIndex}`;
	const hash = hashString(seed);

	const flag = detectFlag(host, sourceIndex);
	const animal = ANIMALS[hash % ANIMALS.length];

	const word = WORDS[Math.floor(hash / ANIMALS.length) % WORDS.length];

	const sparkle = SPARKLES[Math.floor(hash / (ANIMALS.length * WORDS.length)) % SPARKLES.length];

	return `${flag} ${animal} ${word} ${sparkle} · ${protocol.toUpperCase()}`;
}

function detectFlag(host, sourceIndex = 0) {
	const value = String(host || '').toLowerCase();

	const tld = value.match(/\.([a-z]{2})(?:\.|$)/)?.[1];

	if (tld && FLAGS[tld]) {
		return FLAGS[tld];
	}

	const hints = [
		['iran', '🇮🇷'],
		['germany', '🇩🇪'],
		['netherlands', '🇳🇱'],
		['france', '🇫🇷'],
		['finland', '🇫🇮'],
		['turkey', '🇹🇷'],
		['singapore', '🇸🇬'],
		['japan', '🇯🇵'],
		['korea', '🇰🇷'],
	];

	for (const [key, flag] of hints) {
		if (value.includes(key)) {
			return flag;
		}
	}

	return ['🇮🇷', '🌍', '🌐'][sourceIndex % 3];
}

function hashString(value) {
	let hash = 2166136261;

	for (let i = 0; i < value.length; i++) {
		hash ^= value.charCodeAt(i);
		hash = Math.imul(hash, 16777619);
	}

	return hash >>> 0;
}

/* -------------------------------------------------------------------------- */
/* Parsers                                                                    */
/* -------------------------------------------------------------------------- */

function parseVmess(line) {
	try {
		const encoded = line.slice('vmess://'.length).trim();

		if (!encoded) return null;

		const json = atob(normalizeBase64(encoded));
		const data = JSON.parse(json);

		return {
			id: data.id,
			sni: data.sni || data.host || '',
			path: data.path || '/',
			port: Number(data.port || 443),
			net: data.net || '',
			tls: data.tls || 'tls',
		};
	} catch {
		return null;
	}
}

function parseVless(line) {
	try {
		const parsed = new URL(line);
		const params = parsed.searchParams;

		return {
			uuid: decodeURIComponent(parsed.username),
			sni: params.get('sni') || '',
			path: params.get('path') || '/',
			port: Number(parsed.port || 443),
			security: params.get('security') || '',
			type: params.get('type') || '',
		};
	} catch {
		return null;
	}
}

function parseTrojan(line) {
	try {
		const parsed = new URL(line);
		const params = parsed.searchParams;

		return {
			password: decodeURIComponent(parsed.username),
			sni: params.get('sni') || '',
			path: params.get('path') || '/',
			port: Number(parsed.port || 443),
			security: params.get('security') || '',
			type: params.get('type') || '',
		};
	} catch {
		return null;
	}
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

async function fetchTimeout(url, init, timeout) {
	const controller = new AbortController();

	const timer = setTimeout(() => controller.abort(), timeout);

	try {
		return await fetch(url, {
			...init,
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timer);
	}
}

function decodeBase64IfNeeded(value) {
	const compact = value.replace(/\s+/g, '').trim();

	if (!compact) {
		return value;
	}

	if (compact.startsWith('vmess://') || compact.startsWith('vless://') || compact.startsWith('trojan://')) {
		return value;
	}

	try {
		const decoded = atob(normalizeBase64(compact));

		if (decoded.includes('vmess://') || decoded.includes('vless://') || decoded.includes('trojan://')) {
			return decoded;
		}
	} catch {}

	return value;
}

function normalizeBase64(value) {
	const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');

	return normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
}

function normalizePath(path) {
	if (!path) {
		return '/';
	}

	return path.startsWith('/') ? path : `/${path}`;
}

// extract source github account and repo + config type(last url segment) name from url: https://raw.githubusercontent.com/10ium/V2Hub3/main/Split/Normal/trojan.

function extractSourceInfo(url) {
	try {
		const parsed = new URL(url);

		if (parsed.hostname !== 'raw.githubusercontent.com') {
			return null;
		}

		const parts = parsed.pathname.split('/').filter(Boolean);

		if (parts.length < 5) {
			return null;
		}

		const [account, repo, , , ...rest] = parts;

		const type = rest.pop() || '';

		return {
			account,
			repo,
			type,
		};
	} catch {
		return null;
	}
}

function shouldSkipHost(host) {
	const value = String(host || '').toLowerCase();

	return value.includes('workers.dev') || value.includes('pages.dev');
}

function isIp(value) {
	if (!value) return false;

	const parts = value.split('.');

	if (parts.length !== 4) {
		return false;
	}

	return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function parsePositiveInt(value) {
	if (!value || !/^\d+$/.test(value)) {
		return null;
	}

	const number = Number(value);

	return number > 0 ? number : null;
}

function randomItems(array, count) {
	const result = [...array];

	for (let i = result.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));

		[result[i], result[j]] = [result[j], result[i]];
	}

	return result.slice(0, count);
}

function jsonResponse(data) {
	return new Response(JSON.stringify(data, null, 2), {
		headers: {
			'content-type': 'application/json; charset=UTF-8',
			'cache-control': 'no-store',
		},
	});
}

/* -------------------------------------------------------------------------- */
/* Subscription loading page                                                 */
/* -------------------------------------------------------------------------- */

function renderSubLoadingPage(rawSubPath, subscribeUrl) {
	const safeRawSubPath = escapeHtml(rawSubPath);
	const safeSubscribeUrl = escapeHtml(subscribeUrl);

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
  name="viewport"
  content="width=device-width,initial-scale=1,viewport-fit=cover"
/>

<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#08090d">

<title>Node Garden · Checking nodes…</title>

<style>
:root {
  color-scheme: dark;
  font-family:
    Inter,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;

  --bg: #08090d;
  --border: #292d36;
  --text: #f4f4f5;
  --muted: #9298a6;
  --green: #34d399;
  --red: #fb7185;
  --purple: #a78bfa;
}

* {
  box-sizing: border-box;
}

html, body {
  background: var(--bg);
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);

  display: flex;
  align-items: center;
  justify-content: center;

  background:
    radial-gradient(
      circle at 50% -15%,
      rgba(139, 92, 246, .16),
      transparent 42%
    ),
    var(--bg);

  padding: 20px;
}

.card {
  width: min(560px, 100%);

  border: 1px solid var(--border);
  border-radius: 26px;

  background:
    linear-gradient(
      180deg,
      rgba(22, 24, 31, .98),
      rgba(12, 14, 18, .98)
    );

  box-shadow: 0 30px 90px rgba(0, 0, 0, .5);

  padding: clamp(22px, 6vw, 38px);
}

.eyebrow {
  color: var(--purple);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: 11px;
  font-weight: 800;
}

h1 {
  margin: 8px 0 6px;
  font-size: clamp(22px, 6vw, 28px);
  letter-spacing: -.03em;
}

.subtitle {
  margin: 0 0 22px;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.6;
}

.spinner-row {
  display: flex;
  align-items: center;
  gap: 14px;
}

.spinner {
  width: 26px;
  height: 26px;
  flex-shrink: 0;

  border-radius: 50%;
  border: 3px solid #2a2d36;
  border-top-color: var(--purple);

  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.status-text {
  font-size: 13px;
  color: var(--text);
}

.status-sub {
  margin-top: 2px;
  font-size: 12px;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
}

.back-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;

  margin-bottom: 16px;

  color: var(--muted);
  font-size: 12.5px;
  font-weight: 700;
  text-decoration: none;
}

.back-link:hover {
  color: var(--text);
}

.url-box {
  display: flex;
  gap: 8px;
  align-items: center;

  margin-bottom: 18px;
  padding: 8px;

  border: 1px solid var(--border);
  border-radius: 16px;
  background: #090a0e;
}

.url-box code {
  min-width: 0;
  flex: 1;

  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  padding: 8px;

  color: #d4d4d8;
  font-size: 12px;
}

.url-hint {
  margin: -12px 0 20px;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.6;
}

.result {
  display: none;
  margin-top: 22px;
}

.result.visible {
  display: block;
}

.result-summary {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 10px;
}

.result-summary b {
  color: var(--green);
}

.advanced-toggle {
  margin-top: 10px;
  background: none;
  border: none;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-decoration: underline;
  cursor: pointer;
  padding: 4px 0;
  min-height: 0;
}

.advanced-panel {
  display: none;
  margin-top: 10px;
}

.advanced-panel.visible {
  display: block;
}

textarea {
  width: 100%;
  height: 160px;
  resize: vertical;

  border-radius: 14px;
  border: 1px solid var(--border);
  background: #090a0e;

  color: #d4d4d8;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  line-height: 1.5;

  padding: 12px;
}

.actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 9px;
  margin-top: 12px;
}

button {
  min-height: 42px;

  display: inline-flex;
  align-items: center;
  justify-content: center;

  border: 0;
  border-radius: 12px;

  padding: 10px 14px;

  font: inherit;
  font-size: 13px;
  font-weight: 800;

  cursor: pointer;

  background: #f4f4f5;
  color: #18181b;
}

button.secondary {
  color: var(--text);
  background: #24272f;
  border: 1px solid #333741;
}

.error {
  display: none;
  margin-top: 18px;

  border-radius: 14px;
  border: 1px solid rgba(251, 113, 133, .35);
  background: rgba(251, 113, 133, .08);

  padding: 14px;

  color: #fecdd3;
  font-size: 12.5px;
  line-height: 1.6;
}

.error.visible {
  display: block;
}
</style>
</head>

<body>

<div class="card">

<a class="back-link" href="${HOME_ORIGIN}/">← Back to Node Garden</a>

<div class="eyebrow">✨ Node Garden</div>
<h1>Your subscription URL</h1>

<div class="url-box">
<code id="subscribeUrlText">${safeSubscribeUrl}</code>
<button id="copyUrlButton">Copy Subscription Link</button>
</div>
<p class="url-hint">
Paste this link into your client app (v2rayNG, Shadowrocket, etc.) as a
subscription. The app will re-fetch it on its own schedule and always get
a freshly-checked list of working nodes — don't paste raw config text
into the app instead, since that won't auto-update.
</p>

<div class="spinner-row" id="spinnerRow">
<div class="spinner"></div>
<div>
<div class="status-text" id="statusText">Checking nodes right now, as a preview…</div>
<div class="status-sub" id="statusSub">0s elapsed</div>
</div>
</div>

<div class="error" id="errorBox">
Couldn't run a live preview check right now — the URL above still works,
your client app will check it independently.
<button
  class="secondary"
  id="retryButton"
  style="margin-top:10px;width:100%;"
>Retry preview</button>
</div>

<div class="result" id="resultBox">
<div class="result-summary" id="resultSummary"></div>

<button class="advanced-toggle" id="advancedToggle">
Show raw config list (advanced)
</button>

<div class="advanced-panel" id="advancedPanel">
<textarea id="resultText" readonly></textarea>
<div class="actions">
<button id="copyButton">Copy list</button>
<button class="secondary" id="downloadButton">Download .txt</button>
</div>
</div>
</div>

</div>

<script>
const rawUrl = ${JSON.stringify(safeRawSubPath)};
const subscribeUrl = ${JSON.stringify(safeSubscribeUrl)};

const spinnerRow = document.getElementById("spinnerRow");
const statusSub = document.getElementById("statusSub");
const errorBox = document.getElementById("errorBox");
const retryButton = document.getElementById("retryButton");
const resultBox = document.getElementById("resultBox");
const resultSummary = document.getElementById("resultSummary");
const resultText = document.getElementById("resultText");
const copyButton = document.getElementById("copyButton");
const downloadButton = document.getElementById("downloadButton");
const copyUrlButton = document.getElementById("copyUrlButton");
const advancedToggle = document.getElementById("advancedToggle");
const advancedPanel = document.getElementById("advancedPanel");

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    return true;
  }
}

copyUrlButton.addEventListener("click", async () => {
  await copyText(subscribeUrl);
  copyUrlButton.textContent = "Copied ✓";
  setTimeout(() => { copyUrlButton.textContent = "Copy Subscription Link"; }, 1400);
});

advancedToggle.addEventListener("click", () => {
  const isVisible = advancedPanel.classList.toggle("visible");
  advancedToggle.textContent = isVisible
    ? "Hide raw config list"
    : "Show raw config list (advanced)";
});

let elapsedTimer = null;
let startedAt = 0;

function startTimer() {
  startedAt = Date.now();

  clearInterval(elapsedTimer);

  elapsedTimer = setInterval(() => {
    const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
    statusSub.textContent = seconds + "s elapsed";
  }, 100);
}

function stopTimer() {
  clearInterval(elapsedTimer);
}

async function loadSubscription() {
  spinnerRow.style.display = "flex";
  errorBox.classList.remove("visible");
  resultBox.classList.remove("visible");

  startTimer();

  try {
    const response = await fetch(rawUrl, {
      headers: { accept: "text/plain" },
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const text = await response.text();

    const total = response.headers.get("x-total-configs") || "?";
    const checked = response.headers.get("x-checked-configs") || "?";
    const skipped = response.headers.get("x-skipped-for-subrequest-budget") || "0";
    const working = response.headers.get("x-working-configs") || "?";

    stopTimer();
    spinnerRow.style.display = "none";

    let summary =
      "Just now, this URL returned <b>" + working +
      "</b> working node(s) out of " + checked +
      " checked (" + total + " found total)";

    if (Number(skipped) > 0) {
      summary += " · " + skipped + " skipped due to platform subrequest limits";
    }

    resultSummary.innerHTML = summary;
    resultText.value = text;
    resultBox.classList.add("visible");
  } catch (err) {
    stopTimer();
    spinnerRow.style.display = "none";
    errorBox.classList.add("visible");
  }
}

retryButton.addEventListener("click", loadSubscription);

copyButton.addEventListener("click", async () => {
  await copyText(resultText.value);
  copyButton.textContent = "Copied ✓";
  setTimeout(() => { copyButton.textContent = "Copy list"; }, 1400);
});

downloadButton.addEventListener("click", () => {
  const blob = new Blob([resultText.value], { type: "text/plain" });
  const link = document.createElement("a");

  link.href = URL.createObjectURL(blob);
  link.download = "subscription.txt";
  link.click();

  URL.revokeObjectURL(link.href);
});

loadSubscription();
</script>

</body>
</html>`;
}

/* -------------------------------------------------------------------------- */
/* UI                                                                         */
/* -------------------------------------------------------------------------- */

function renderHomePage() {
	const subscriptionUrl = `${SUBSCRIPTION_ORIGIN}/sub`;
	const safeSubscriptionUrl = escapeHtml(subscriptionUrl);

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
  name="viewport"
  content="width=device-width,initial-scale=1,viewport-fit=cover"
/>

<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#08090d">

<title>Node Garden</title>

<style>
:root {
  color-scheme: dark;
  font-family:
    Inter,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;

  --bg: #08090d;
  --card: #111318;
  --card-2: #15171d;
  --border: #292d36;
  --text: #f4f4f5;
  --muted: #9298a6;
  --green: #34d399;
  --red: #fb7185;
  --yellow: #fbbf24;
  --purple: #a78bfa;
}

* {
  box-sizing: border-box;
}

html {
  background: var(--bg);
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);

  background:
    radial-gradient(
      circle at 50% -15%,
      rgba(139, 92, 246, .16),
      transparent 42%
    ),
    var(--bg);

  padding:
    max(18px, env(safe-area-inset-top))
    16px
    max(24px, env(safe-area-inset-bottom));
}

.container {
  width: min(760px, 100%);
  margin: 0 auto;
}

.card {
  margin-top: 18px;

  border: 1px solid var(--border);
  border-radius: 26px;

  background:
    linear-gradient(
      180deg,
      rgba(22, 24, 31, .98),
      rgba(12, 14, 18, .98)
    );

  box-shadow:
    0 30px 90px rgba(0, 0, 0, .5);

  padding: clamp(20px, 5vw, 38px);
}

.header {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
}

.eyebrow {
  color: var(--purple);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: 11px;
  font-weight: 800;
}

h1 {
  margin: 8px 0 10px;

  font-size: clamp(30px, 7vw, 46px);
  line-height: 1;
  letter-spacing: -.045em;
}

.description {
  margin: 0;

  max-width: 650px;

  color: var(--muted);

  font-size: 14px;
  line-height: 1.7;
}

.badge {
  white-space: nowrap;

  border: 1px solid var(--border);
  border-radius: 999px;

  background: rgba(255,255,255,.025);

  padding: 8px 11px;

  color: var(--muted);

  font-size: 11px;
}

.subscription {
  display: flex;
  gap: 8px;
  align-items: center;

  margin-top: 26px;

  padding: 8px;

  border:
    1px solid var(--border);

  border-radius: 16px;

  background: #090a0e;
}

.subscription code {
  min-width: 0;
  flex: 1;

  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  padding: 8px;

  color: #d4d4d8;
  font-size: 14px;
}

button,
.button {
  min-height: 42px;

  display: inline-flex;
  align-items: center;
  justify-content: center;

  border: 0;
  border-radius: 12px;

  padding: 10px 14px;

  font: inherit;
  font-size: 13px;
  font-weight: 800;

  cursor: pointer;

  background: #f4f4f5;
  color: #18181b;

  text-decoration: none;
}

button.secondary {
  color: var(--text);
  background: #24272f;
  border: 1px solid #333741;
}

button:disabled {
  opacity: .55;
  cursor: wait;
}

.actions {
  display: grid;
  grid-template-columns: 1fr 1fr;

  gap: 9px;

  margin-top: 10px;
}

.status {
  margin-top: 30px;
  padding-top: 22px;

  border-top: 1px solid var(--border);
}

.status-header {
  display: flex;
  justify-content: space-between;
  align-items: center;

  gap: 12px;

  margin-bottom: 12px;
}

.status-title {
  display: flex;
  align-items: center;
  gap: 9px;
}

.status-title h2 {
  margin: 0;

  font-size: 15px;
}

.status-summary {
  color: #717782;
  font-size: 12px;
}

.pulse {
  width: 8px;
  height: 8px;

  border-radius: 50%;

  background: var(--yellow);
}

.pulse.ready {
  background: var(--green);

  box-shadow:
    0 0 12px rgba(52, 211, 153, .45);
}

.source {
  display: grid;

  grid-template-columns:
    auto
    minmax(0, 1fr)
    auto;

  align-items: center;

  gap: 10px;

  border: 1px solid #414141;
  border-radius: 10px;
  margin: 0.5rem;
  padding: 12px;
  font-size: 12px;
}

.source:last-child {
  border-bottom: 0;
}

.dot {
  width: 8px;
  height: 8px;

  border-radius: 50%;

  background: #71717a;
}

.dot.ok {
  background: var(--green);

  box-shadow:
    0 0 9px rgba(52, 211, 153, .35);
}

.dot.bad {
  background: var(--red);
}

.source-url {
  min-width: 0;

  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  color: #d4d4d8;
}

.source-meta {
  white-space: nowrap;

  color: #717782;

  font-variant-numeric: tabular-nums;
}

.empty {
  padding: 15px 0;

  color: #717782;
  font-size: 12px;
}

.footer {
  margin-top: 24px;
  padding-top: 18px;

  border-top: 1px solid var(--border);

  color: #717782;

  font-size: 11px;
  line-height: 1.7;
}

.footer-links {
  display: flex;
  flex-wrap: wrap;

  gap: 12px;

  margin-top: 7px;
}

.footer a {
  color: #a1a1aa;
  text-decoration: none;
}

.footer a:hover {
  color: white;
}

.note {
  margin-top: 10px;
  color: #555a65;
}

@media (max-width: 600px) {
  body {
    padding-left: 10px;
    padding-right: 10px;
  }

  .card {
    margin-top: 8px;
    border-radius: 21px;
    padding: 20px 16px;
  }

  .header {
    display: block;
  }

  .badge {
    display: inline-flex;
    margin-top: 13px;
  }

  .actions {
    grid-template-columns: 1fr;
  }

  .subscription {
    align-items: stretch;
  }

  .subscription button {
    flex-shrink: 0;
  }

  .source {
    grid-template-columns:
      auto
      minmax(0, 1fr);

    row-gap: 5px;
  }

  .source-meta {
    grid-column: 2;
  }
}
</style>
</head>

<body>

<main class="container">

<section class="card">

<div class="header">

<div>
<div class="eyebrow">✨ Node Garden</div>

<h1>Healthy nodes</h1>

<p class="description">
Live-check subscription sources and WebSocket endpoints,
then return only working configurations.
</p>
</div>

<div class="badge" id="checkedAt">
Live status
</div>

</div>

<div class="subscription">

<code id="subscriptionLink">
${safeSubscriptionUrl}
</code>

<a
class="button"
  href="${safeSubscriptionUrl}"
  target="_blank"
  rel="noreferrer">
Open
</a>

</div>

<div class="actions">

<button
  id="copyButton" 
>
Copy Subscription
</button>

<button
  class="secondary"
  id="refreshButton"
>
Refresh sources
</button>

</div>

<section class="status">

<div class="status-header">

<div class="status-title">

<span
  class="pulse"
  id="statusPulse"
></span>

<h2>Source status</h2>

</div>

<span
  class="status-summary"
  id="statusSummary"
>
Checking…
</span>

</div>

<div id="sources">
<div class="empty">
Checking subscription sources…
</div>
</div>

</section>

<footer class="footer">

<div>
Built with Cloudflare Workers · TLS + WebSocket transport checks
</div>

<div class="footer-links">
<a href="${HOME_ORIGIN}/fa">فارسی ↗</a>
<a
  href="https://github.com/ehsanghaffar"
  target="_blank"
>
GitHub ↗
</a>

<a
  href="https://eindev.ir?utm_source=cloudflare_worker&utm_medium=referral&utm_campaign=worker_link"
  target="_blank"
  rel="noreferrer"
>
eindev.ir ↗
</a>

</div>

<div class="note">
Transport checks verify that the endpoint accepts a WebSocket
connection. They do not authenticate VLESS/Trojan credentials.
</div>

</footer>

</section>

</main>

<script>
const sourcesEl =
  document.getElementById("sources");

const summaryEl =
  document.getElementById("statusSummary");

const pulseEl =
  document.getElementById("statusPulse");

const refreshEl =
  document.getElementById("refreshButton");

const copyEl =
  document.getElementById("copyButton");

const checkedEl =
  document.getElementById("checkedAt");

const subscriptionEl =
  document.getElementById("subscriptionLink");

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    })[char]
  );
}

async function refreshSources() {
  refreshEl.disabled = true;
  refreshEl.textContent = "Checking…";

  summaryEl.textContent = "Checking…";
  checkedEl.textContent = "Checking";
  pulseEl.classList.remove("ready");

  sourcesEl.innerHTML =
    '<div class="empty">Checking subscription sources…</div>';

  try {
    const controller =
      new AbortController();

    const timeout =
      setTimeout(
        () => controller.abort(),
        15000
      );

    const response =
      await fetch(
        "/api/sub-links?_=" +
        Date.now(),
        {
          cache: "no-store",
          signal: controller.signal,
        }
      );

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(
        "HTTP " + response.status
      );
    }

    const data =
      await response.json();

    const results =
      Array.isArray(data.results)
        ? data.results
        : [];

    if (!results.length) {
      sourcesEl.innerHTML =
        '<div class="empty">No sources configured.</div>';

      summaryEl.textContent =
        "0 sources";

      return;
    }

    let online = 0;

    sourcesEl.innerHTML =
      results
        .map((item) => {
          const ok = item.ok === true;

          if (ok) {
            online++;
          }

          const status =
            ok
              ? "Online"
              : item.status
                ? "HTTP " + item.status
                : "Offline";

          const latency =
            Number.isFinite(item.latencyMs)
              ? " · " +
                item.latencyMs +
                "ms"
              : "";

          return \`
<div class="source">
  <span class="dot \${ok ? "ok" : "bad"}"></span>

  <span
    class="source-url"
    title="\${escapeHtml(item.url || "")}"
  >
    \${escapeHtml(item.url.substring(item.url.indexOf("com") + 4, item.url.lastIndexOf("/") || ""))}
  </span>

  <span class="source-meta">
    \${status}\${latency}
  </span>
</div>
\`;
        })
        .join("");

    summaryEl.textContent =
      online +
      "/" +
      results.length +
      " online";

    checkedEl.textContent =
      "Checked " +
      new Date().toLocaleTimeString(
        [],
        {
          hour: "2-digit",
          minute: "2-digit",
        }
      );

    pulseEl.classList.add("ready");

  } catch {
    sourcesEl.innerHTML =
      '<div class="empty">Could not load source status.</div>';

    summaryEl.textContent =
      "Check failed";

    checkedEl.textContent =
      "Unavailable";

  } finally {
    refreshEl.disabled = false;
    refreshEl.textContent =
      "Refresh sources";
  }
}

async function copySubscription() {
  const value = ${JSON.stringify(subscriptionUrl)};

  try {
    await navigator.clipboard.writeText(
      value
    );
  } catch {
    const textarea =
      document.createElement("textarea");

    textarea.value = value;

    document.body.appendChild(
      textarea
    );

    textarea.select();

    document.execCommand(
      "copy"
    );

    textarea.remove();
  }

  subscriptionEl.textContent =
    value;

  copyEl.textContent =
    "Copied ✓";

  setTimeout(() => {
    copyEl.textContent =
      "Copy";
  }, 1400);
}

refreshEl.addEventListener(
  "click",
  refreshSources
);

copyEl.addEventListener(
  "click",
  copySubscription
);

// Important: run immediately.
refreshSources();
</script>

</body>
</html>`;
}

function renderHomePageFa() {
	const subscriptionUrl = `${SUBSCRIPTION_ORIGIN}/sub`;
	const safeSubscriptionUrl = escapeHtml(subscriptionUrl);

	return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta
  name="viewport"
  content="width=device-width,initial-scale=1,viewport-fit=cover"
/>

<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#08090d">

<title>باغ نود</title>

<style>
:root {
  color-scheme: dark;
  font-family:
    Vazirmatn,
    Tahoma,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;

  --bg: #08090d;
  --card: #111318;
  --card-2: #15171d;
  --border: #292d36;
  --text: #f4f4f5;
  --muted: #9298a6;
  --green: #34d399;
  --red: #fb7185;
  --yellow: #fbbf24;
  --purple: #a78bfa;
}

* {
  box-sizing: border-box;
}

html {
  background: var(--bg);
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);

  background:
    radial-gradient(
      circle at 50% -15%,
      rgba(139, 92, 246, .16),
      transparent 42%
    ),
    var(--bg);

  padding:
    max(18px, env(safe-area-inset-top))
    16px
    max(24px, env(safe-area-inset-bottom));
}

.container {
  width: min(760px, 100%);
  margin: 0 auto;
}

.card {
  margin-top: 18px;

  border: 1px solid var(--border);
  border-radius: 26px;

  background:
    linear-gradient(
      180deg,
      rgba(22, 24, 31, .98),
      rgba(12, 14, 18, .98)
    );

  box-shadow:
    0 30px 90px rgba(0, 0, 0, .5);

  padding: clamp(20px, 5vw, 38px);
}

.header {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
}

.eyebrow {
  color: var(--purple);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: 11px;
  font-weight: 800;
}

h1 {
  margin: 8px 0 10px;

  font-size: clamp(30px, 7vw, 46px);
  line-height: 1;
  letter-spacing: -.02em;
}

.description {
  margin: 0;

  max-width: 650px;

  color: var(--muted);

  font-size: 14px;
  line-height: 1.7;
}

.badge {
  white-space: nowrap;

  border: 1px solid var(--border);
  border-radius: 999px;

  background: rgba(255,255,255,.025);

  padding: 8px 11px;

  color: var(--muted);

  font-size: 11px;
}

.subscription {
  display: flex;
  gap: 8px;
  align-items: center;

  margin-top: 26px;

  padding: 8px;

  border:
    1px solid var(--border);

  border-radius: 16px;

  background: #090a0e;
}

.subscription code {
  min-width: 0;
  flex: 1;

  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  padding: 8px;

  color: #d4d4d8;
  font-size: 12px;
  direction: ltr;
  text-align: left;
}

button,
.button {
  min-height: 42px;

  display: inline-flex;
  align-items: center;
  justify-content: center;

  border: 0;
  border-radius: 12px;

  padding: 10px 14px;

  font: inherit;
  font-size: 13px;
  font-weight: 800;

  cursor: pointer;

  background: #f4f4f5;
  color: #18181b;

  text-decoration: none;
}

button.secondary {
  color: var(--text);
  background: #24272f;
  border: 1px solid #333741;
}

button:disabled {
  opacity: .55;
  cursor: wait;
}

.actions {
  display: grid;
  grid-template-columns: 1fr 1fr;

  gap: 9px;

  margin-top: 10px;
}

.status {
  margin-top: 30px;
  padding-top: 22px;

  border-top: 1px solid var(--border);
}

.status-header {
  display: flex;
  justify-content: space-between;
  align-items: center;

  gap: 12px;

  margin-bottom: 12px;
}

.status-title {
  display: flex;
  align-items: center;
  gap: 9px;
}

.status-title h2 {
  margin: 0;

  font-size: 15px;
}

.status-summary {
  color: #717782;
  font-size: 12px;
}

.pulse {
  width: 8px;
  height: 8px;

  border-radius: 50%;

  background: var(--yellow);
}

.pulse.ready {
  background: var(--green);

  box-shadow:
    0 0 12px rgba(52, 211, 153, .45);
}
    
div#sources {

    display: flex;
    flex-direction: column;
    gap: 0.5rem;

}

.source {
  display: grid;

  grid-template-columns:
    auto
    minmax(0, 1fr)
    auto;

  align-items: center;

  gap: 10px;

  padding: 12px 0;

  border-bottom: 1px solid #1f2229;

  font-size: 12px;
}

.source:last-child {
  border-bottom: 0;
}

.dot {
  width: 8px;
  height: 8px;

  border-radius: 50%;

  background: #71717a;
}

.dot.ok {
  background: var(--green);

  box-shadow:
    0 0 9px rgba(52, 211, 153, .35);
}

.dot.bad {
  background: var(--red);
}

.source-url {
  min-width: 0;

  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  color: #d4d4d8;
  direction: ltr;
  text-align: right;
}

.source-meta {
  white-space: nowrap;

  color: #717782;

  font-variant-numeric: tabular-nums;
}

.empty {
  padding: 15px 0;

  color: #717782;
  font-size: 12px;
}

.footer {
  margin-top: 24px;
  padding-top: 18px;

  border-top: 1px solid var(--border);

  color: #717782;

  font-size: 11px;
  line-height: 1.7;
}

.footer-links {
  display: flex;
  flex-wrap: wrap;

  gap: 12px;

  margin-top: 7px;
}

.footer a {
  color: #a1a1aa;
  text-decoration: none;
}

.footer a:hover {
  color: white;
}

.note {
  margin-top: 10px;
  color: #555a65;
}

@media (max-width: 600px) {
  body {
    padding-left: 10px;
    padding-right: 10px;
  }

  .card {
    margin-top: 8px;
    border-radius: 21px;
    padding: 20px 16px;
  }

  .header {
    display: block;
  }

  .badge {
    display: inline-flex;
    margin-top: 13px;
  }

  .actions {
    grid-template-columns: 1fr;
  }

  .subscription {
    align-items: stretch;
  }

  .subscription button {
    flex-shrink: 0;
  }

  .source {
    grid-template-columns:
      auto
      minmax(0, 1fr);

    row-gap: 5px;
  }

  .source-meta {
    grid-column: 2;
  }
}
</style>
</head>

<body>

<main class="container">

<section class="card">

<div class="header">

<div>
<div class="eyebrow">✨ باغ نود</div>

<h1>نودهای سالم</h1>

<p class="description">
منابع اشتراک و اتصال‌های WebSocket را به‌صورت زنده بررسی می‌کنیم
و فقط پیکربندی‌های سالم را برمی‌گردانیم.
</p>
</div>

<div class="badge" id="checkedAt">
وضعیت زنده
</div>

</div>

<div class="subscription">

<code id="subscriptionLink">
${safeSubscriptionUrl}
</code>

<a href="${safeSubscriptionUrl}" target="_blank" class="button">
باز کردن
</a>

</div>

<div class="actions">
<button
  id="copyButton"
>
کپی کردن لینک اشتراک
</button>

<button
  class="secondary"
  id="refreshButton"
>
بررسی مجدد منابع
</button>

</div>

<section class="status">

<div class="status-header">

<div class="status-title">

<span
  class="pulse"
  id="statusPulse"
></span>

<h2>وضعیت منابع</h2>

</div>

<span
  class="status-summary"
  id="statusSummary"
>
در حال بررسی…
</span>

</div>

<div id="sources">
<div class="empty">
در حال بررسی منابع اشتراک…
</div>
</div>

</section>

<footer class="footer">

<div>
ساخته‌شده با Cloudflare Workers · بررسی اتصال TLS و WebSocket
</div>

<div class="footer-links">

<a
  href="https://github.com/ehsanghaffar"
  target="_blank"
>
گیت‌هاب ↗
</a>

<a
  href="https://eindev.ir?utm_source=cloudflare_worker&utm_medium=referral&utm_campaign=worker_link"
  target="_blank"
  rel="noreferrer"
>
eindev.ir ↗
</a>

<a href="${HOME_ORIGIN}/">English ↗</a>

</div>

</footer>

</section>

</main>

<script>
const sourcesEl =
  document.getElementById("sources");

const summaryEl =
  document.getElementById("statusSummary");

const pulseEl =
  document.getElementById("statusPulse");

const refreshEl =
  document.getElementById("refreshButton");

const copyEl =
  document.getElementById("copyButton");

const checkedEl =
  document.getElementById("checkedAt");

const subscriptionEl =
  document.getElementById("subscriptionLink");

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    })[char]
  );
}

async function refreshSources() {
  refreshEl.disabled = true;
  refreshEl.textContent = "در حال بررسی…";

  summaryEl.textContent = "در حال بررسی…";
  checkedEl.textContent = "در حال بررسی";
  pulseEl.classList.remove("ready");

  sourcesEl.innerHTML =
    '<div class="empty">در حال بررسی منابع اشتراک…</div>';

  try {
    const controller =
      new AbortController();

    const timeout =
      setTimeout(
        () => controller.abort(),
        15000
      );

    const response =
      await fetch(
        "/api/sub-links?_=" +
        Date.now(),
        {
          cache: "no-store",
          signal: controller.signal,
        }
      );

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(
        "HTTP " + response.status
      );
    }

    const data =
      await response.json();

    const results =
      Array.isArray(data.results)
        ? data.results
        : [];

    if (!results.length) {
      sourcesEl.innerHTML =
        '<div class="empty">هیچ منبعی تنظیم نشده است.</div>';

      summaryEl.textContent =
        "۰ منبع";

      return;
    }

    let online = 0;

    sourcesEl.innerHTML =
      results
        .map((item) => {
          const ok = item.ok === true;

          if (ok) {
            online++;
          }

          const status =
            ok
              ? "آنلاین"
              : item.status
                ? "HTTP " + item.status
                : "آفلاین";

          const latency =
            Number.isFinite(item.latencyMs)
              ? " · " +
                item.latencyMs +
                "ms"
              : "";

          return \`
<div class="source">
  <span class="dot \${ok ? "ok" : "bad"}"></span>

  <span
    class="source-url"
    title="\${escapeHtml(item.url || "")}"
  >
    \${escapeHtml(item.url || "")}
  </span>

  <span class="source-meta">
    \${status}\${latency}
  </span>
</div>
\`;
        })
        .join("");

    summaryEl.textContent =
      online +
      " از " +
      results.length +
      " آنلاین";

    checkedEl.textContent =
      "بررسی‌شده در " +
      new Date().toLocaleTimeString(
        "fa-IR",
        {
          hour: "2-digit",
          minute: "2-digit",
        }
      );

    pulseEl.classList.add("ready");

  } catch {
    sourcesEl.innerHTML =
      '<div class="empty">دریافت وضعیت منابع ناموفق بود.</div>';

    summaryEl.textContent =
      "بررسی ناموفق";

    checkedEl.textContent =
      "در دسترس نیست";

  } finally {
    refreshEl.disabled = false;
    refreshEl.textContent =
      "بررسی مجدد منابع";
  }
}

async function copySubscription() {
  const value = ${JSON.stringify(subscriptionUrl)};

  try {
    await navigator.clipboard.writeText(
      value
    );
  } catch {
    const textarea =
      document.createElement("textarea");

    textarea.value = value;

    document.body.appendChild(
      textarea
    );

    textarea.select();

    document.execCommand(
      "copy"
    );

    textarea.remove();
  }

  subscriptionEl.textContent =
    value;

  copyEl.textContent =
    "کپی شد ✓";

  setTimeout(() => {
    copyEl.textContent =
      "کپی کردن لینک اشتراک";
  }, 1400);
}

refreshEl.addEventListener(
  "click",
  refreshSources
);

copyEl.addEventListener(
  "click",
  copySubscription
);

// Important: run immediately.
refreshSources();
</script>

</body>
</html>`;
}

/* -------------------------------------------------------------------------- */
/* HTML escape                                                                */
/* -------------------------------------------------------------------------- */

function escapeHtml(value) {
	return String(value)
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#039;');
}
