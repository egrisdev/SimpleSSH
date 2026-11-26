// Terminal front-end hosted in WebView2. Talks to TerminalView.xaml.cs via chrome.webview messages.
//   page -> host: ready, input, binary, resize, copy, paste, title, fontSize
//   host -> page: output, paste, focus, fit, clear, options
(() => {
  'use strict';

  const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));
  const params = new URLSearchParams(location.search);
  const defaultFontSize = clamp(parseInt(params.get('fontSize') || '14', 10) || 14, 6, 40);
  let fontSize = defaultFontSize;
  const fontFamily = params.get('fontFamily') || "'Cascadia Mono', Consolas, 'Courier New', monospace";
  // Copy on select (per connection, on by default): selecting copies, and right click always pastes (PuTTY style).
  let copyOnSelect = params.get('copyOnSelect') !== '0';

  const host = window.chrome && window.chrome.webview;
  const post = (msg) => { if (host) host.postMessage(msg); };

  const term = new Terminal({
    cursorBlink: true,
    fontFamily,
    fontSize,
    scrollback: 10000,
    rightClickSelectsWord: false,
    theme: {
      background: '#1e1e1e', foreground: '#d4d4d4', cursor: '#aeafad', cursorAccent: '#1e1e1e',
      selectionBackground: '#264f78',
      black: '#000000', red: '#cd3131', green: '#0dbc79', yellow: '#e5e510',
      blue: '#2472c8', magenta: '#bc3fbc', cyan: '#11a8cd', white: '#e5e5e5',
      brightBlack: '#666666', brightRed: '#f14c4c', brightGreen: '#23d18b', brightYellow: '#f5f543',
      brightBlue: '#3b8eea', brightMagenta: '#d670d6', brightCyan: '#29b8db', brightWhite: '#ffffff',
    },
  });

  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  const el = document.getElementById('terminal');
  term.open(el);

  function safeFit() {
    try {
      if (el.clientWidth > 0 && el.clientHeight > 0) fit.fit();
    } catch (_) { /* not attached yet */ }
  }
  safeFit();

  let resizeTimer = 0;
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(safeFit, 25);
  }).observe(el);

  term.onData((data) => post({ type: 'input', data }));
  term.onBinary((data) => post({ type: 'binary', data }));
  term.onResize(({ cols, rows }) => post({ type: 'resize', cols, rows }));
  term.onTitleChange((title) => post({ type: 'title', title }));
  // OSC 7 (file://host/path): shells that report their folder, so Open files can start there.
  term.parser.registerOscHandler(7, (data) => { post({ type: 'cwd', data }); return true; });

  function copySelection() {
    const text = term.getSelection();
    if (text) post({ type: 'copy', text });
    term.clearSelection();
  }

  function requestPaste() {
    post({ type: 'paste' });
  }

  // Every paste goes through SimpleSSH, which removes hidden control characters first: also a paste the browser
  // starts by itself (drag and drop of text, Edit menu), which xterm.js would otherwise send unchecked.
  el.addEventListener('paste', (e) => { e.preventDefault(); e.stopImmediatePropagation(); requestPaste(); }, true);
  el.addEventListener('drop', (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);

  function setFontSize(size) {
    const next = clamp(size, 6, 40);
    if (next === fontSize) return;
    fontSize = next;
    term.options.fontSize = fontSize;
    safeFit();
    post({ type: 'fontSize', size: fontSize });
  }

  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== 'keydown') return true;
    const ctrl = e.ctrlKey && !e.altKey && !e.metaKey;
    const key = (e.key || '').toLowerCase();
    const stop = () => { e.preventDefault(); e.stopPropagation(); return false; };

    // Copy: Ctrl+Shift+C always, Ctrl+C only when there is a selection (otherwise it is SIGINT).
    if (ctrl && key === 'c' && (e.shiftKey || term.hasSelection())) { copySelection(); return stop(); }
    // Paste: Ctrl+V, Ctrl+Shift+V, Shift+Insert.
    if (ctrl && key === 'v') { requestPaste(); return stop(); }
    if (e.shiftKey && !e.ctrlKey && !e.altKey && e.key === 'Insert') { requestPaste(); return stop(); }
    // Font zoom.
    if (ctrl && !e.shiftKey && (key === '=' || key === '+')) { setFontSize(fontSize + 1); return stop(); }
    if (ctrl && !e.shiftKey && key === '-') { setFontSize(fontSize - 1); return stop(); }
    if (ctrl && !e.shiftKey && key === '0') { setFontSize(defaultFontSize); return stop(); }
    return true;
  });

  // Right click: with copy on select it always pastes (the selection is already copied); otherwise it copies
  // if something is selected and pastes if not (Windows Terminal style).
  el.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    if (copyOnSelect) { term.clearSelection(); requestPaste(); }
    else if (term.hasSelection()) copySelection(); else requestPaste();
  });

  // Copy on select: copy when the mouse lets go of a selection (drag, double click word, triple click line).
  // The selection stays visible. The same text right after (the double click's own mouseup) is not copied twice.
  let lastAutoCopy = { text: '', at: 0 };
  function copyIfSelected() {
    if (!copyOnSelect) return;
    const text = term.getSelection();
    const now = Date.now();
    if (!text || (text === lastAutoCopy.text && now - lastAutoCopy.at < 600)) return;
    lastAutoCopy = { text, at: now };
    post({ type: 'copy', text });
  }
  document.addEventListener('mouseup', (e) => { if (e.button === 0) setTimeout(copyIfSelected, 0); });
  el.addEventListener('dblclick', () => setTimeout(copyIfSelected, 0));

  el.addEventListener('wheel', (e) => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    setFontSize(fontSize + (e.deltaY < 0 ? 1 : -1));
  }, { passive: false });

  if (host) {
    host.addEventListener('message', (e) => {
      const m = e.data;
      if (!m || typeof m !== 'object') return;
      switch (m.type) {
        case 'output': term.write(m.data); break;
        case 'paste': if (m.text) term.paste(m.text); term.focus(); break;
        case 'focus': safeFit(); term.focus(); break;
        case 'fit': safeFit(); break;
        case 'clear': term.clear(); break;
        case 'options': if (typeof m.copyOnSelect === 'boolean') copyOnSelect = m.copyOnSelect; break;
      }
    });
  }

  post({ type: 'ready', cols: term.cols, rows: term.rows });
  term.focus();
})();
