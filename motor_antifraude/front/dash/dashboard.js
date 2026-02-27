// dashboard.js — Dashboard Antifraude Plux
// Conectado a GET /v1/dashboard/summary (datos reales desde la BD)
// ⚠️ Sin simulación. Sin setInterval. Sin mocks.

const API_BASE = 'http://localhost:8000';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const kpiVolume = document.getElementById('kpi-volume');
const kpiVolumeChange = document.getElementById('kpi-volume-change');
const kpiRejection = document.getElementById('kpi-rejection');
const kpiRejChange = document.getElementById('kpi-rej-change');
const kpiAlerts = document.getElementById('kpi-alerts');
const kpiAlertsBadge = document.getElementById('kpi-alerts-badge');
const kpiApproved = document.getElementById('kpi-approved');
const txFeed = document.getElementById('tx-feed');
const geoTableBody = document.getElementById('geo-table-body');
const heatmapContainer = document.getElementById('heatmap-container');
const identityList = document.getElementById('identity-list');
const lastUpdated = document.getElementById('last-updated');
const periodSelect = document.getElementById('period-select');
const refreshBtn = document.getElementById('refresh-btn');
const loadingOverlay = document.getElementById('loading-overlay');

// ── País → emoji flag ─────────────────────────────────────────────────────────
const FLAG = {
  EC: '🇪🇨', US: '🇺🇸', MX: '🇲🇽', CO: '🇨🇴', PE: '🇵🇪',
  ES: '🇪🇸', RU: '🇷🇺', CN: '🇨🇳', NG: '🇳🇬', DE: '🇩🇪',
  BR: '🇧🇷', AR: '🇦🇷', XX: '🌐',
};
function flag(c) { return (c && FLAG[c]) ? FLAG[c] : (c || '?'); }

// ── Acción → estilos ──────────────────────────────────────────────────────────
function actionStyle(action) {
  if (!action) return { color: '#6b7280', bg: '#f3f4f6', label: 'Desconocida' };
  if (action === 'ACTION_APPROVE') return { color: '#16a34a', bg: '#f0fdf4', label: '✅ Aprobada' };
  if (action.includes('BLOCK')) return { color: '#dc2626', bg: '#fef2f2', label: '🚨 Bloqueada' };
  if (action.includes('CHALLENGE')) return { color: '#d97706', bg: '#fffbeb', label: '⚠️ Challenge' };
  return { color: '#6b7280', bg: '#f3f4f6', label: action };
}

// ── Score → color ──────────────────────────────────────────────────────────────
function scoreColor(score) {
  if (score <= 20) return '#16a34a';
  if (score <= 70) return '#d97706';
  return '#dc2626';
}

// ── Formateo ──────────────────────────────────────────────────────────────────
function fmtMoney(v) {
  return '$' + Number(v).toLocaleString('es-EC', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function fmtTime(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleTimeString('es-EC', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDate(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleString('es-EC', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

// ── Animación de número ───────────────────────────────────────────────────────
function animateNum(el, target, prefix = '', suffix = '', decimals = 0) {
  if (!el) return;
  const start = 0;
  const duration = 800;
  const startTime = performance.now();
  function step(now) {
    const p = Math.min((now - startTime) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    const val = start + (target - start) * ease;
    el.textContent = prefix + val.toFixed(decimals) + suffix;
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Mostrar/ocultar overlay de carga ─────────────────────────────────────────
function setLoading(loading) {
  if (loadingOverlay) loadingOverlay.style.display = loading ? 'flex' : 'none';
  if (refreshBtn) {
    refreshBtn.disabled = loading;
    refreshBtn.style.opacity = loading ? '0.5' : '1';
  }
}

// ── Render KPIs ───────────────────────────────────────────────────────────────
function renderKPIs(kpis) {
  animateNum(kpiVolume, kpis.total_volume, '$', '', 2);
  animateNum(kpiRejection, kpis.rejection_rate_pct, '', '%', 1);
  animateNum(kpiAlerts, kpis.critical_alerts_last_hour, '', '', 0);
  animateNum(kpiApproved, kpis.approved_tx, '', '', 0);

  if (kpis.critical_alerts_last_hour > 0 && kpiAlertsBadge) {
    kpiAlertsBadge.style.display = 'inline-flex';
  } else if (kpiAlertsBadge) {
    kpiAlertsBadge.style.display = 'none';
  }

  // Textos de contexto
  if (kpiVolumeChange) kpiVolumeChange.textContent = `${kpis.total_tx} evaluaciones`;
  if (kpiRejChange) kpiRejChange.textContent = `${kpis.rejected_tx} bloqueadas · ${kpis.challenged_tx} con challenge`;
}

// ── Render Feed Transaccional ─────────────────────────────────────────────────
function renderFeed(items) {
  if (!txFeed) return;
  if (!items || items.length === 0) {
    txFeed.innerHTML = `
            <li style="text-align:center;color:#9ca3af;font-size:12px;padding:1.5rem;">
                Sin transacciones en el período seleccionado
            </li>`;
    return;
  }

  txFeed.innerHTML = items.map(tx => {
    const st = actionStyle(tx.action);
    return `
        <li class="feed-item" style="padding:10px 0;border-bottom:1px solid #f3f4f6;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
                <div style="min-width:0;flex:1;">
                    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                        <span style="font-size:11px;font-family:monospace;color:#374151;font-weight:600;">
                            ${tx.card_bin}XXXXXX
                        </span>
                        <span style="font-size:10px;color:#9ca3af;">·</span>
                        <span style="font-size:11px;font-weight:600;color:${scoreColor(tx.risk_score)};">
                            Score ${tx.risk_score}
                        </span>
                    </div>
                    <p style="font-size:11px;color:#8b5cf6;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                        ${tx.merchant_name || '—'}
                    </p>
                </div>
                <div style="text-align:right;flex-shrink:0;">
                    <p style="font-size:12px;font-weight:700;color:#111827;">${fmtMoney(tx.amount)} ${tx.currency}</p>
                    <span style="display:inline-block;margin-top:3px;font-size:10px;font-weight:600;
                                 padding:2px 8px;border-radius:999px;
                                 background:${st.bg};color:${st.color};">
                        ${st.label}
                    </span>
                </div>
            </div>
            <p style="font-size:10px;color:#9ca3af;margin-top:4px;">${fmtTime(tx.timestamp)} · ${tx.transaction_type}</p>
        </li>`;
  }).join('');
}

// ── Render Discrepancias Geográficas ──────────────────────────────────────────
function renderGeo(items) {
  if (!geoTableBody) return;
  if (!items || items.length === 0) {
    geoTableBody.innerHTML = `
            <tr><td colspan="5" style="text-align:center;color:#9ca3af;font-size:12px;padding:1.5rem;">
                Sin discrepancias geográficas en el período
            </td></tr>`;
    return;
  }

  geoTableBody.innerHTML = items.map(g => {
    const st = actionStyle(g.action);
    const mismatch = g.is_mismatch;
    const rowBg = mismatch ? '#fff7ed' : 'transparent';
    return `
        <tr style="background:${rowBg};border-bottom:1px solid #f3f4f6;">
            <td style="padding:8px 12px;font-size:11px;font-family:monospace;color:#6b7280;">
                ${g.ip_address || '—'}
            </td>
            <td style="padding:8px 12px;font-size:12px;">
                ${flag(g.ip_country)} ${g.ip_country || '?'}
            </td>
            <td style="padding:8px 12px;font-size:12px;">
                ${flag(g.gps_country)} ${g.gps_country || '?'}
                ${mismatch ? '<span style="font-size:10px;color:#f97316;margin-left:4px;font-weight:700;">⚠ Mismatch</span>' : ''}
            </td>
            <td style="padding:8px 12px;">
                <span style="font-size:11px;font-weight:700;color:${scoreColor(g.risk_score)};">
                    ${g.risk_score}
                </span>
            </td>
            <td style="padding:8px 12px;">
                <span style="font-size:10px;padding:2px 8px;border-radius:999px;
                             background:${st.bg};color:${st.color};font-weight:600;">
                    ${st.label}
                </span>
            </td>
        </tr>`;
  }).join('');
}

// ── Render Heatmap de Comercios ────────────────────────────────────────────────
function renderHeatmap(items) {
  if (!heatmapContainer) return;
  if (!items || items.length === 0) {
    heatmapContainer.innerHTML = `
            <p style="color:#9ca3af;font-size:12px;text-align:center;padding:1rem;">
                Sin datos de comercios en el período
            </p>`;
    return;
  }

  const maxFraud = Math.max(...items.map(i => i.fraud_count), 1);

  heatmapContainer.innerHTML = items.map(m => {
    const pct = Math.round((m.fraud_count / maxFraud) * 100);
    const danger = m.fraud_rate_pct > 20;
    const barColor = danger
      ? 'linear-gradient(to right,#f87171,#dc2626)'
      : 'linear-gradient(to right,#fb923c,#f97316)';
    return `
        <div style="margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px;">
                <span style="font-size:12px;font-weight:600;color:#374151;
                             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:60%;">
                    ${m.merchant_name}
                </span>
                <div style="text-align:right;flex-shrink:0;margin-left:8px;">
                    <span style="font-size:12px;font-weight:700;color:${danger ? '#dc2626' : '#f97316'};">
                        ${m.fraud_count} fraudes
                    </span>
                    <span style="font-size:10px;color:#9ca3af;margin-left:4px;">/ ${m.total_count}</span>
                    <span style="font-size:10px;font-weight:600;
                                 padding:1px 6px;border-radius:999px;margin-left:6px;
                                 background:${danger ? '#fef2f2' : '#fff7ed'};
                                 color:${danger ? '#dc2626' : '#d97706'};">
                        ${m.fraud_rate_pct.toFixed(1)}%
                    </span>
                </div>
            </div>
            <div style="height:8px;background:#f3f4f6;border-radius:999px;overflow:hidden;">
                <div style="height:100%;width:${pct}%;background:${barColor};
                            border-radius:999px;transition:width 0.7s ease;"></div>
            </div>
        </div>`;
  }).join('');
}

// ── Render Identity Risks ─────────────────────────────────────────────────────
function renderIdentity(items) {
  if (!identityList) return;
  if (!items || items.length === 0) {
    identityList.innerHTML = `
            <li style="color:#9ca3af;font-size:12px;text-align:center;padding:1rem;list-style:none;">
                Sin usuarios de alto riesgo en el período
            </li>`;
    return;
  }

  const riskColors = {
    HIGH: { bg: '#fef2f2', text: '#dc2626', border: '#fca5a5' },
    MEDIUM: { bg: '#fffbeb', text: '#d97706', border: '#fcd34d' },
    LOW: { bg: '#f0fdf4', text: '#16a34a', border: '#86efac' },
  };

  identityList.innerHTML = items.map(u => {
    const c = riskColors[u.risk_level] || riskColors.LOW;
    const userId = u.user_id.slice(0, 8) + '…';
    return `
        <li style="display:flex;align-items:center;gap:12px;padding:10px 0;
                   border-bottom:1px solid #f3f4f6;list-style:none;">
            <div style="width:36px;height:36px;border-radius:10px;flex-shrink:0;
                        background:${c.bg};border:1px solid ${c.border};
                        display:flex;align-items:center;justify-content:center;
                        font-size:14px;font-weight:800;color:${c.text};">
                ${u.distinct_bins}
            </div>
            <div style="flex:1;min-width:0;">
                <p style="font-size:11px;font-family:monospace;color:#374151;font-weight:600;">
                    ${userId}
                </p>
                <p style="font-size:10px;color:#9ca3af;margin-top:1px;">
                    ${u.tx_count} txs · Score máx: ${u.max_risk_score}
                </p>
            </div>
            <div style="text-align:right;flex-shrink:0;">
                <span style="font-size:10px;font-weight:700;
                             padding:3px 9px;border-radius:999px;
                             background:${c.bg};color:${c.text};border:1px solid ${c.border};">
                    ${u.risk_level}
                </span>
                <p style="font-size:10px;color:#9ca3af;margin-top:2px;">
                    ${u.distinct_bins} BINs distintos
                </p>
            </div>
        </li>`;
  }).join('');
}

// ── Fetch principal ───────────────────────────────────────────────────────────
async function fetchDashboard(periodHours = 24) {
  const token = localStorage.getItem('plux_token');
  if (!token) {
    showToast('No hay sesión activa. Redirigiendo al login…', 'error');
    setTimeout(() => { window.location.href = '../auth/login.html'; }, 1500);
    return;
  }

  setLoading(true);

  try {
    const url = `${API_BASE}/v1/dashboard/summary?period_hours=${periodHours}&feed_limit=20&geo_limit=30`;
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (res.status === 401 || res.status === 403) {
      localStorage.removeItem('plux_token');
      window.location.href = '../auth/login.html';
      return;
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.detail || `Error ${res.status}`);
    }

    const data = await res.json();

    // Renderizar todos los módulos
    renderKPIs(data.kpis);
    renderFeed(data.transaction_feed);
    renderGeo(data.geo_discrepancies);
    renderHeatmap(data.merchant_heatmap);
    renderIdentity(data.identity_risks);

    // Timestamp de última actualización
    if (lastUpdated) {
      lastUpdated.textContent = 'Actualizado: ' + new Date().toLocaleTimeString('es-EC');
    }

  } catch (err) {
    console.error('[Plux Dashboard] Error:', err);
    showToast(`Error al cargar datos: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg, type = 'error') {
  const prev = document.getElementById('dash-toast');
  if (prev) prev.remove();
  const colors = {
    error: { bg: '#fef2f2', border: '#fca5a5', text: '#b91c1c' },
    success: { bg: '#f0fdf4', border: '#86efac', text: '#166534' },
  };
  const c = colors[type] || colors.error;
  const t = document.createElement('div');
  t.id = 'dash-toast';
  t.style.cssText = [
    'position:fixed', 'bottom:20px', 'right:20px', 'z-index:9999',
    `background:${c.bg}`, `border:1.5px solid ${c.border}`, `color:${c.text}`,
    'border-radius:12px', 'padding:12px 18px',
    'font-size:13px', 'font-weight:600', 'font-family:Inter,sans-serif',
    'box-shadow:0 8px 30px rgba(0,0,0,0.12)', 'cursor:pointer', 'max-width:380px',
  ].join(';');
  t.textContent = msg;
  document.body.appendChild(t);
  t.addEventListener('click', () => t.remove());
  setTimeout(() => t?.remove(), 5000);
}

// ── Logout ────────────────────────────────────────────────────────────────────
function handleLogout() {
  localStorage.removeItem('plux_token');
  localStorage.removeItem('plux_user_id');
  window.location.href = '../auth/login.html';
}

// ── Inicialización ────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  // User en el footer/header
  const userId = localStorage.getItem('plux_user_id');
  const footerUser = document.getElementById('footer-user');
  if (userId && footerUser) footerUser.textContent = `ID: ${userId.slice(0, 8)}…`;

  // Cargar datos iniciales
  const period = periodSelect ? parseInt(periodSelect.value) : 24;
  fetchDashboard(period);

  // Cambio de período
  if (periodSelect) {
    periodSelect.addEventListener('change', () => {
      fetchDashboard(parseInt(periodSelect.value));
    });
  }

  // Botón de refresh manual
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      const p = periodSelect ? parseInt(periodSelect.value) : 24;
      fetchDashboard(p);
    });
  }
});
