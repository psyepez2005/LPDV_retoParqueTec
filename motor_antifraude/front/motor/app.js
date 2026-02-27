// app.js — Motor Antifraude Plux
// Integración real con POST /v1/transactions/evaluate
// ⚠️ Solo frontend — no se toca el backend.

const API_BASE = 'http://localhost:8000';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const analyzeButton = document.getElementById('analyzeButton');
const payloadInput = document.getElementById('payloadInput');
const stateInitial = document.getElementById('stateInitial');
const stateLoading = document.getElementById('stateLoading');
const stateResult = document.getElementById('stateResult');
const scoreValue = document.getElementById('scoreValue');
const scoreBar = document.getElementById('scoreBar');
const verdictAlert = document.getElementById('verdictAlert');
const verdictTitle = document.getElementById('verdictTitle');
const verdictMessage = document.getElementById('verdictMessage');
const verdictChip = document.getElementById('verdictChip');
const analysisTime = document.getElementById('analysis-time');
const modeBadge = document.getElementById('mode-badge');
const analyzeText = document.getElementById('analyze-text');
const analyzeSpinner = document.getElementById('analyze-spinner');
const footerUser = document.getElementById('footer-user');
const breakdownPanel = document.getElementById('breakdownPanel');
const bdMetaGrid = document.getElementById('bdMetaGrid');
const bdRows = document.getElementById('bdRows');

// ── Payload de prueba por defecto ─────────────────────────────────────────────
const DEFAULT_PAYLOAD = {
  "user_id": "a0000001-0000-4000-a000-000000000001",
  "device_id": "device-legitimo-001",
  "card_bin": "410001",
  "amount": "150.00",
  "currency": "MXN",
  "ip_address": "187.210.100.50",
  "latitude": 19.43,
  "longitude": -99.13,
  "transaction_type": "TOP_UP",
  "recipient_id": null,
  "session_id": "c0000001-0000-4000-c000-000000000001",
  "timestamp": "2026-02-26T14:00:00Z",
  "user_agent": "PluxWallet/2.1.0 (Android 13; Samsung Galaxy A54)",
  "sdk_version": "android-2.1.0",
  "device_os": "android",
  "device_model": "Samsung Galaxy A54",
  "is_rooted_device": false,
  "is_emulator": false,
  "network_type": "4g",
  "battery_level": 72,
  "account_age_days": 180,
  "avg_monthly_amount": "500.00",
  "tx_count_last_30_days": 8,
  "failed_tx_last_7_days": 0,
  "time_since_last_tx_minutes": 1440,
  "kyc_level": "full",
  "session_duration_seconds": 120,
  "form_fill_time_seconds": 45,
  "card_last4": "4321",
  "is_international_card": false,
  "merchant_category": "ECOMMERCE",
  "merchant_id": null,
  "merchant_name": "Amazon MX",
  "ip_country": "MX"
};

// ── Temas visuales por nivel de riesgo ───────────────────────────────────────
// level 0 = Seguro (0-20), 1 = Sospechoso (21-70), 2 = Fraude (71-100)
const RISK_THEMES = [
  {
    scoreColor: '#16a34a',
    barGradient: 'linear-gradient(to right, #4ade80, #16a34a)',
    alertBg: '#f0fdf4',
    alertBorder: '#22c55e',
    textColor: '#166534',
    chipBg: '#dcfce7',
    chipColor: '#166534',
    chipIcon: '<polyline points="20 6 9 17 4 12"/>',
    chipLabel: '✅ Aprobada',
    badgeLabel: 'Aprobada',
    title: 'Aprobada — Transacción Segura',
    message: 'Score de riesgo bajo. El patrón de uso es consistente con el historial. La transacción pasa directamente sin fricción adicional.',
  },
  {
    scoreColor: '#d97706',
    barGradient: 'linear-gradient(to right, #fbbf24, #d97706)',
    alertBg: '#fffbeb',
    alertBorder: '#f59e0b',
    textColor: '#92400e',
    chipBg: '#fef3c7',
    chipColor: '#92400e',
    chipIcon: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    chipLabel: '⚠️ Sospechosa',
    badgeLabel: 'Sospechosa',
    title: 'Sospechosa — Validación Secundaria',
    message: 'Se detectaron señales de anomalía. Se recomienda verificación adicional (OTP / challenge) antes de liberar los fondos.',
  },
  {
    scoreColor: '#dc2626',
    barGradient: 'linear-gradient(to right, #f87171, #dc2626)',
    alertBg: '#fef2f2',
    alertBorder: '#ef4444',
    textColor: '#991b1b',
    chipBg: '#fee2e2',
    chipColor: '#991b1b',
    chipIcon: '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    chipLabel: '🚨 Fraude',
    badgeLabel: 'Fraude',
    title: 'Rechazada — Fraude Detectado',
    message: 'El patrón coincide con vectores de fraude conocidos. Transacción bloqueada automáticamente. Escalar al área de investigaciones.',
  },
];

// ── Inicialización ────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  // Mostrar user ID en footer
  const userId = localStorage.getItem('plux_user_id');
  if (userId && footerUser) {
    footerUser.textContent = `ID: ${userId.slice(0, 8)}…`;
  }

  showState('initial');
});

// ── Gestión de estados de la UI ───────────────────────────────────────────────
function showState(state) {
  stateInitial.style.display = (state === 'initial') ? 'flex' : 'none';
  stateLoading.style.display = (state === 'loading') ? 'flex' : 'none';
  stateResult.style.display = (state === 'result') ? 'block' : 'none';
}

function setButtonLoading(loading) {
  analyzeButton.disabled = loading;
  if (analyzeText) analyzeText.textContent = loading ? 'Analizando…' : 'Ejecutar Análisis de Riesgo';
  if (analyzeSpinner) analyzeSpinner.style.display = loading ? 'block' : 'none';
}

// ── Lógica de negocio: determinar nivel de riesgo ────────────────────────────
function getRiskLevel(score) {
  if (score <= 20) return 0;  // Seguro
  if (score <= 70) return 1;  // Sospechoso
  return 2;                   // Fraude
}

// ── Aplicar tema visual según nivel ──────────────────────────────────────────
function applyTheme(level, score) {
  const t = RISK_THEMES[level];

  // Score numérico
  scoreValue.textContent = String(Math.round(score));
  scoreValue.style.color = t.scoreColor;

  // Barra de riesgo (animada)
  setTimeout(() => {
    scoreBar.style.width = `${Math.min(score, 100)}%`;
    scoreBar.style.background = t.barGradient;
  }, 80);

  // Caja de alerta
  verdictAlert.style.background = t.alertBg;
  verdictAlert.style.borderColor = t.alertBorder;
  verdictAlert.style.borderLeftColor = t.alertBorder;

  // Textos
  verdictTitle.textContent = t.title;
  verdictTitle.style.color = t.textColor;
  verdictMessage.textContent = t.message;
  verdictMessage.style.color = t.textColor;

  // Chip de veredicto
  verdictChip.style.background = t.chipBg;
  verdictChip.style.color = t.chipColor;
  verdictChip.innerHTML = `
        <svg style="flex-shrink:0;" width="12" height="12" fill="none" stroke="currentColor"
             stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
            ${t.chipIcon}
        </svg>
        ${t.chipLabel}
    `;

  // Badge en la cabecera de la card
  if (modeBadge) {
    modeBadge.textContent = t.badgeLabel;
    modeBadge.style.background = t.chipBg;
    modeBadge.style.color = t.chipColor;
    modeBadge.style.borderColor = t.alertBorder;
  }
}

// ── Mostrar resultado final ───────────────────────────────────────────────────
function showResultState(score, data) {
  showState('result');
  const level = getRiskLevel(score);
  applyTheme(level, score);
  renderBreakdown(data);
  console.info('[Plux Motor] Respuesta completa del backend:', data);
}

// ── Render del panel de justificación ────────────────────────────────────────
function renderBreakdown(data) {
  if (!breakdownPanel || !bdMetaGrid || !bdRows) return;

  // ─ Metadatos clave ──────────────────────────────────────────────────────────
  const actionLabel = {
    ACTION_APPROVE: '✅ Aprobada',
    ACTION_CHALLENGE: '⚠️ Challenge',
    ACTION_REJECT: '🚨 Rechazada',
  };

  const meta = [
    { label: 'Decisión', value: actionLabel[data.action] ?? data.action },
    { label: 'Tiempo respuesta', value: `${data.response_time_ms ?? '—'} ms` },
    { label: 'Score total', value: `${data.risk_score} / 100` },
    {
      label: 'TX ID', value: data.transaction_id
        ? data.transaction_id.slice(0, 8) + '…'
        : '—'
    },
  ];

  bdMetaGrid.innerHTML = meta.map(m => `
    <div class="bd-meta-item">
      <div class="bd-meta-label">${m.label}</div>
      <div class="bd-meta-value">${m.value}</div>
    </div>
  `).join('');

  // ─ Score breakdown rows ─────────────────────────────────────────────────────
  const breakdown = data.score_breakdown ?? [];

  if (breakdown.length === 0) {
    bdRows.innerHTML = '<p style="font-size:12px;color:#9ca3af;">Sin detalle disponible.</p>';
  } else {
    bdRows.innerHTML = breakdown.map(item => {
      let ptBg, ptColor;
      if (item.points === 0) {
        ptBg = '#f0fdf4'; ptColor = '#16a34a';
      } else if (item.points <= 2) {
        ptBg = '#fffbeb'; ptColor = '#d97706';
      } else {
        ptBg = '#fef2f2'; ptColor = '#dc2626';
      }

      return `
        <div class="breakdown-row">
          <div class="bd-points" style="background:${ptBg};color:${ptColor};">
            +${item.points}
          </div>
          <div style="flex:1;min-width:0;">
            <div class="bd-category">${item.category ?? ''}</div>
            <div class="bd-code">${item.code}</div>
            <div class="bd-desc">${item.description ?? ''}</div>
          </div>
        </div>
      `;
    }).join('');
  }

  breakdownPanel.style.display = 'block';
}


// ── Reset a estado inicial ────────────────────────────────────────────────────
function resetState() {
  showState('initial');
  scoreBar.style.width = '0%';
  if (breakdownPanel) breakdownPanel.style.display = 'none';
  if (modeBadge) {
    modeBadge.textContent = 'En espera';
    modeBadge.style.background = '#f5f3ff';
    modeBadge.style.color = '#7c3aed';
    modeBadge.style.borderColor = '#ede9fe';
  }
}


// ── Toast de error ────────────────────────────────────────────────────────────
function showErrorToast(message) {
  const prev = document.getElementById('motor-toast');
  if (prev) prev.remove();

  const toast = document.createElement('div');
  toast.id = 'motor-toast';
  toast.style.cssText = [
    'position:fixed', 'bottom:24px', 'right:24px', 'z-index:9999',
    'background:#fef2f2', 'border:1.5px solid #fca5a5', 'color:#b91c1c',
    'border-radius:14px', 'padding:14px 18px',
    'display:flex', 'align-items:flex-start', 'gap:12px',
    'font-size:13px', 'font-weight:600', 'font-family:Inter,sans-serif',
    'box-shadow:0 8px 30px rgba(0,0,0,0.15)', 'cursor:pointer',
    'max-width:420px',
  ].join(';');

  toast.innerHTML = `
        <svg style="flex-shrink:0;margin-top:1px;" width="16" height="16" fill="none" stroke="#ef4444"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span style="flex:1;line-height:1.5;">${message}</span>
        <button onclick="this.parentElement.remove()"
                style="background:none;border:none;cursor:pointer;color:#b91c1c;
                       font-size:18px;line-height:1;padding:0;flex-shrink:0;">×</button>
    `;

  document.body.appendChild(toast);
  toast.addEventListener('click', () => toast.remove());
  setTimeout(() => toast?.remove(), 6000);
}

// ── Manejador principal del botón ─────────────────────────────────────────────
analyzeButton.addEventListener('click', async () => {
  const rawPayload = payloadInput.value.trim();

  // 1. Validar que el textarea contenga JSON válido
  let parsedPayload;
  try {
    parsedPayload = JSON.parse(rawPayload);
  } catch (err) {
    showErrorToast('⚠️ El JSON del payload es inválido. Revisa el formato antes de enviar.');
    return;
  }

  // 2. Verificar que haya sesión activa
  const token = localStorage.getItem('plux_token');
  if (!token) {
    showErrorToast('No hay sesión activa. Redirigiendo al login…');
    setTimeout(() => { window.location.href = '../auth/login.html'; }, 1500);
    return;
  }

  // 3. Mostrar estado de carga
  showState('loading');
  setButtonLoading(true);

  const startTime = Date.now();

  try {
    const response = await fetch(`${API_BASE}/v1/transactions/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
        'x-signature': 'dummy_signature_123',
      },
      body: JSON.stringify(parsedPayload),
    });

    const elapsed = Date.now() - startTime;
    if (analysisTime) analysisTime.textContent = `${elapsed} ms · FastAPI`;

    const data = await response.json();

    if (!response.ok) {
      // Extraer mensaje de error del backend (Pydantic o custom)
      let errMsg;
      if (typeof data?.detail === 'string') {
        errMsg = data.detail;
      } else if (Array.isArray(data?.detail)) {
        errMsg = data.detail.map(e => `${e.loc?.slice(-1)?.[0] ?? ''}: ${e.msg}`).join(' · ');
      } else {
        errMsg = `Error ${response.status} — ${response.statusText}`;
      }
      console.error('[Plux Motor] Error del backend:', data);
      showState('initial');
      showErrorToast(`Error ${response.status}: ${errMsg}`);
      return;
    }

    // 4. Extraer risk_score de la respuesta
    const score = parseFloat(data.risk_score ?? data.score ?? 0);
    showResultState(score, data);

  } catch (err) {
    console.error('[Plux Motor] Error de red:', err);
    showState('initial');
    showErrorToast('No se pudo conectar con el backend. Verifica que el servidor Docker esté activo en el puerto 8000.');
  } finally {
    setButtonLoading(false);
  }
});

// ── Logout global ─────────────────────────────────────────────────────────────
function handleLogout() {
  localStorage.removeItem('plux_token');
  localStorage.removeItem('plux_user_id');
  window.location.href = '../auth/login.html';
}