(() => {
  'use strict';

  const DEFAULT = Object.freeze({
    theme: 'default',
    backgroundImageUrl: '',
    panelOpacity: 0.74,
    panelBlurPx: 18,
    customCss: '',
    customScript: '',
  });
  const MAX_CSS = 20000;
  const MAX_SCRIPT = 12000;
  let authenticated = false;
  let scriptHasRun = false;
  const $ = (selector) => document.querySelector(selector);
  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

  function toast(message, bad = false) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = message;
    el.className = `toast show${bad ? ' bad' : ''}`;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { el.className = 'toast'; }, 3600);
  }

  function normalizeSettings(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('外观配置格式无效');
    const settings = { ...DEFAULT, ...value };
    if (!['default', 'custom'].includes(settings.theme)) throw new Error('主题选项无效');
    if (typeof settings.backgroundImageUrl !== 'string' || settings.backgroundImageUrl.length > 2048) throw new Error('背景图片 URL 最多 2048 个字符');
    settings.backgroundImageUrl = settings.backgroundImageUrl.trim();
    if (settings.backgroundImageUrl) {
      let imageUrl;
      try { imageUrl = new URL(settings.backgroundImageUrl); } catch { throw new Error('请输入有效的 HTTPS 图片 URL'); }
      if (imageUrl.protocol !== 'https:' || imageUrl.username || imageUrl.password) throw new Error('背景图片只接受不含账号密码的 HTTPS 地址');
      settings.backgroundImageUrl = imageUrl.href;
    }
    settings.panelOpacity = Number(settings.panelOpacity);
    if (!Number.isFinite(settings.panelOpacity) || settings.panelOpacity < 0.45 || settings.panelOpacity > 0.92) throw new Error('面板透明度须在 0.45–0.92 之间');
    settings.panelBlurPx = Number(settings.panelBlurPx);
    if (!Number.isInteger(settings.panelBlurPx) || settings.panelBlurPx < 0 || settings.panelBlurPx > 32) throw new Error('模糊度须为 0–32 px 的整数');
    if (typeof settings.customCss !== 'string' || settings.customCss.length > MAX_CSS) throw new Error('自定义 CSS 最多 20000 个字符');
    if (typeof settings.customScript !== 'string' || settings.customScript.length > MAX_SCRIPT) throw new Error('自定义 Script 最多 12000 个字符');
    return settings;
  }

  function fromForm() {
    return normalizeSettings({
      theme: $('#appearance-theme').value,
      backgroundImageUrl: $('#appearance-background').value,
      panelOpacity: $('#appearance-opacity').value,
      panelBlurPx: $('#appearance-blur').value,
      customCss: $('#appearance-css').value,
      customScript: $('#appearance-script').value,
    });
  }

  function setForm(settings) {
    $('#appearance-theme').value = settings.theme;
    $('#appearance-background').value = settings.backgroundImageUrl;
    $('#appearance-opacity').value = String(settings.panelOpacity);
    $('#appearance-blur').value = String(settings.panelBlurPx);
    $('#appearance-css').value = settings.customCss;
    $('#appearance-script').value = settings.customScript;
    updateRangeLabels();
    updateBackgroundPreview();
    toggleCustomCss();
  }

  function updateRangeLabels() {
    $('#appearance-opacity-value').value = Number($('#appearance-opacity').value).toFixed(2);
    $('#appearance-blur-value').value = `${$('#appearance-blur').value} px`;
  }

  function toggleCustomCss() {
    $('#appearance-css-field').classList.toggle('hidden', $('#appearance-theme').value !== 'custom');
  }

  function updateBackgroundPreview() {
    const image = $('#appearance-background-preview');
    const value = $('#appearance-background').value.trim();
    if (!value || value.length > 2048) {
      image.removeAttribute('src');
      image.classList.add('hidden');
      return;
    }
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error('HTTPS only');
      image.src = url.href;
      image.classList.remove('hidden');
    } catch {
      image.removeAttribute('src');
      image.classList.add('hidden');
    }
  }

  function applyAppearance(settings, runScript = false) {
    if (!authenticated || !$('#app') || $('#app').classList.contains('hidden')) return;
    const app = $('#app');
    app.dataset.appearanceTheme = settings.theme;
    app.style.setProperty('--panel-opacity', String(settings.panelOpacity));
    app.style.setProperty('--panel-blur', `${settings.panelBlurPx}px`);

    if (settings.backgroundImageUrl) {
      const safeUrl = new URL(settings.backgroundImageUrl).href;
      document.body.style.backgroundImage = `linear-gradient(115deg, rgba(4, 8, 20, .70) 0%, rgba(7, 12, 29, .45) 46%, rgba(5, 10, 23, .55) 100%), url(${JSON.stringify(safeUrl)})`;
      document.body.style.backgroundPosition = 'center, center';
      document.body.style.backgroundSize = 'cover, cover';
      document.body.style.backgroundAttachment = 'fixed, fixed';
    } else {
      document.body.style.removeProperty('background-image');
      document.body.style.removeProperty('background-position');
      document.body.style.removeProperty('background-size');
      document.body.style.removeProperty('background-attachment');
    }

    let customStyle = $('#appearance-custom-css');
    if (!customStyle) {
      customStyle = document.createElement('style');
      customStyle.id = 'appearance-custom-css';
      document.head.appendChild(customStyle);
    }
    customStyle.textContent = settings.theme === 'custom' ? settings.customCss : '';

    if (runScript && !scriptHasRun && settings.customScript.trim()) {
      scriptHasRun = true;
      try {
        const wrapper = settings.customScript.match(/^\s*<script(?:\s+([^>]*)?)?>([\s\S]*)<\/script>\s*$/i);
        if (wrapper && /\bsrc\s*=/i.test(wrapper[1] || '')) throw new Error('仅支持内联代码，不支持外部 script URL');
        const code = wrapper ? wrapper[2] : settings.customScript;
        if (!wrapper && /<\/?script\b/i.test(code)) throw new Error('请填写纯 JavaScript，或用单个 script 标签包裹');
        new Function(`"use strict";\n${code}`)();
      } catch (error) {
        toast(`自定义 Script 执行失败：${error.message}`, true);
      }
    }
  }

  async function authenticatedAppReady(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const response = await fetch('/api/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (response.ok && !$('#app').classList.contains('hidden')) {
          authenticated = true;
          return true;
        }
      } catch { /* retry briefly while the login request settles */ }
      await delay(300);
    }
    return false;
  }

  async function loadAndApply() {
    if (!authenticated) return;
    try {
      const response = await fetch('/api/settings/appearance', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.error || `请求失败（${response.status}）`);
      const settings = normalizeSettings(data.appearance || DEFAULT);
      setForm(settings);
      applyAppearance(settings, true);
      $('#appearance-status').textContent = '已加载';
      $('#appearance-status').className = 'pill online';
    } catch (error) {
      const settings = normalizeSettings(DEFAULT);
      setForm(settings);
      applyAppearance(settings, false);
      $('#appearance-status').textContent = '读取失败';
      $('#appearance-status').className = 'pill warning';
      toast(`外观设置读取失败：${error.message}`, true);
    }
  }

  async function save(settings) {
    if (!authenticated) throw new Error('请先登录');
    const response = await fetch('/api/settings/appearance', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ appearance: settings }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error || `保存失败（${response.status}）`);
    const saved = normalizeSettings(data.appearance || settings);
    setForm(saved);
    applyAppearance(saved, false);
    $('#appearance-status').textContent = '已保存';
    $('#appearance-status').className = 'pill online';
    return saved;
  }

  async function initializeAuthenticatedView(timeoutMs) {
    if (await authenticatedAppReady(timeoutMs)) await loadAndApply();
  }

  $('#login-form')?.addEventListener('submit', () => { void initializeAuthenticatedView(15000); });
  $('#appearance-theme').addEventListener('change', toggleCustomCss);
  $('#appearance-opacity').addEventListener('input', updateRangeLabels);
  $('#appearance-blur').addEventListener('input', updateRangeLabels);
  $('#appearance-background').addEventListener('input', updateBackgroundPreview);

  $('#appearance-preview').addEventListener('click', () => {
    try {
      const settings = fromForm();
      if (!authenticated) throw new Error('请先登录');
      applyAppearance(settings, false);
      toast('仅本次已登录会话预览，尚未保存。预览不会执行自定义 Script。');
    } catch (error) { toast(error.message, true); }
  });

  $('#appearance-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const settings = fromForm();
      await save(settings);
      toast('外观已保存。自定义 Script 会在下次加载已认证面板时执行。');
    } catch (error) { toast(`保存失败：${error.message}`, true); }
  });

  $('#appearance-reset').addEventListener('click', async () => {
    if (!window.confirm('恢复默认主题会清空已保存的背景、CSS 和 Script 设置。是否继续？')) return;
    try {
      setForm(normalizeSettings(DEFAULT));
      await save(normalizeSettings(DEFAULT));
      toast('已恢复并保存默认外观。');
    } catch (error) { toast(`恢复失败：${error.message}`, true); }
  });

  void (async () => {
    try {
      const response = await fetch('/api/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (response.ok) await initializeAuthenticatedView(10000);
    } catch { /* logged out: do not load or execute injected settings */ }
  })();
})();
