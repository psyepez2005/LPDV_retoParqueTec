// ============================================================
// dashboard.js — Lógica del Dashboard Antifraude · Plux v1
// ============================================================
// Este archivo maneja la interactividad y los datos simulados
// del dashboard analítico. Cuando el backend esté listo,
// reemplaza las funciones de mock por llamadas reales a la API.
// ============================================================

// ── Referencias al DOM ──────────────────────────────────────

const kpiVolume = document.getElementById("kpi-volume");
const kpiRejection = document.getElementById("kpi-rejection");
const kpiAlerts = document.getElementById("kpi-alerts");
const kpiAlertsBadge = document.getElementById("kpi-alerts-badge");
const txFeed = document.getElementById("tx-feed");

// ── Estado interno del dashboard ────────────────────────────

const state = {
  totalVolume: 0,
  totalTx: 0,
  rejectedTx: 0,
  criticalAlerts: 0,
};

// ── Datos de muestra ────────────────────────────────────────

const MOCK_COUNTRIES = [
  { code: "EC", name: "🇪🇨 Ecuador" },
  { code: "MX", name: "🇲🇽 México" },
  { code: "CO", name: "🇨🇴 Colombia" },
  { code: "PE", name: "🇵🇪 Perú" },
  { code: "US", name: "🇺🇸 EE.UU." },
  { code: "ES", name: "🇪🇸 España" },
  { code: "RU", name: "🇷🇺 Rusia" },
  { code: "CN", name: "🇨🇳 China" },
];

const MOCK_BINS = ["411111", "524356", "378282", "601100", "356600", "650031"];

const MOCK_MERCHANTS = ["Maxiplus S.A.", "Aki Tiendas", "TuPrecio Online", "FarmaExpress", "Kiwi Market"];

// ============================================================
// GENERADOR DE DATOS SIMULADOS (Mock Data Generator)
// ============================================================
/**
 * Genera un objeto de transacción simulada que imita la estructura
 * descrita en pilin.md.txt.
 *
 * TODO: Cuando el backend de FastAPI esté listo, eliminar esta función
 *       y reemplazar por un fetch/WebSocket al endpoint real.
 *       Ejemplo orientativo:
 *
 *       const ws = new WebSocket("ws://localhost:8000/ws/transactions");
 *       ws.onmessage = (event) => {
 *         const tx = JSON.parse(event.data);
 *         handleNewTransaction(tx);
 *       };
 */
function generateMockTransaction() {
  const ipCountry = MOCK_COUNTRIES[Math.floor(Math.random() * MOCK_COUNTRIES.length)];
  const shippingCountry = MOCK_COUNTRIES[Math.floor(Math.random() * MOCK_COUNTRIES.length)];
  const totalValue = parseFloat((Math.random() * 2500).toFixed(2));
  const bin = MOCK_BINS[Math.floor(Math.random() * MOCK_BINS.length)];
  const isFraud = ipCountry.code !== shippingCountry.code && Math.random() > 0.4;
  const isHighValue = totalValue > 1000;

  return {
    // Variables del dataset (pilin.md.txt)
    OrderDate: new Date().toISOString(),
    CreditCardFirst6: bin,                         // BIN del emisor
    TotalValue: totalValue,
    IPAddress: `${randomIP()}`,
    ShippingCountry: shippingCountry.name,
    IPCountry: ipCountry.name,
    CustomerLegalDocument: `${randomDoc()}`,
    CustomerEMail: `user${randomInt(100, 9999)}@mail.com`,
    CustomerPhoneNumber: `+${randomInt(1, 599)} ${randomInt(600, 999)} ${randomInt(1000, 9999)}`,
    RUC: `${randomInt(10000000, 99999999)}001`,
    MerchantName: MOCK_MERCHANTS[Math.floor(Math.random() * MOCK_MERCHANTS.length)],
    // Campos calculados para la UI
    _isFraud: isFraud,
    _isHighValue: isHighValue,
  };
}

// ── Helpers de generación ────────────────────────────────────

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP() {
  return `${randomInt(10, 220)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;
}

function randomDoc() {
  return String(randomInt(1000000000, 9999999999));
}

// ============================================================
// FUNCIONES DE RENDERIZADO
// ============================================================

/**
 * Actualiza los KPIs superiores con los datos del estado global.
 *
 * TODO: Reemplazar `state` por la respuesta de:
 *       GET /api/kpis?date=today
 *       Esperar objeto: { totalVolume, totalTx, rejectedTx, criticalAlerts }
 */
function renderKPIs() {
  const rejectionRate = state.totalTx > 0
    ? ((state.rejectedTx / state.totalTx) * 100).toFixed(1)
    : "0.0";

  kpiVolume.textContent = `$${state.totalVolume.toLocaleString("es-EC", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  kpiRejection.textContent = `${rejectionRate}%`;
  kpiAlerts.textContent = String(state.criticalAlerts);

  // Mostrar badge LIVE si hay alertas críticas
  if (state.criticalAlerts > 0) {
    kpiAlertsBadge.classList.remove("hidden");
  }
}

/**
 * Añade una nueva fila al Feed Transaccional.
 * Se inserta al inicio de la lista para efecto "live feed".
 *
 * TODO: Llamar a esta función con cada mensaje de WebSocket o
 *       con el resultado de GET /api/transactions/latest?limit=20
 *       Mapear los campos del DTO del backend a las variables del dataset.
 *
 * @param {Object} tx - Objeto de transacción (ver generateMockTransaction)
 */
function renderTransactionFeed(tx) {
  // Quita el placeholder inicial si aún existe
  const placeholder = txFeed.querySelector("li.text-center");
  if (placeholder) placeholder.remove();

  const time = new Date(tx.OrderDate).toLocaleTimeString("es-EC", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  // Determinar color según riesgo
  // TODO: Usar el score real del motor antifraude (campo `riskScore` del backend)
  let riskClass = "text-emerald-600";
  let riskLabel = "Seguro";
  if (tx._isFraud && tx._isHighValue) {
    riskClass = "text-red-600";
    riskLabel = "Fraude · Alto Valor";
  } else if (tx._isFraud) {
    riskClass = "text-orange-600";
    riskLabel = "Sospechoso";
  } else if (tx._isHighValue) {
    riskClass = "text-amber-600";
    riskLabel = "Alto Valor";
  }

  const li = document.createElement("li");
  li.className = "feed-item";
  li.innerHTML = `
    <div class="flex items-center justify-between gap-2">
      <div class="min-w-0">
        <div class="flex items-center gap-1.5 flex-wrap">
          <span class="text-[11px] font-mono text-gray-700">${tx.CreditCardFirst6}XXXXXX</span>
          <span class="text-[10px] text-gray-400">·</span>
          <span class="text-[11px] text-gray-600">${tx.ShippingCountry}</span>
        </div>
        <p class="text-xs text-purple-500 mt-0.5 truncate">${tx.MerchantName}</p>
      </div>
      <div class="text-right flex-shrink-0">
        <p class="text-xs font-bold ${tx._isHighValue ? "text-amber-600" : "text-gray-900"}">
          $${tx.TotalValue.toLocaleString("es-EC", { minimumFractionDigits: 2 })}
        </p>
        <p class="text-[10px] ${riskClass} font-medium">${riskLabel}</p>
      </div>
    </div>
    <p class="text-[10px] text-gray-400 mt-1">${time}</p>
  `;

  // Insertar al inicio
  txFeed.insertBefore(li, txFeed.firstChild);

  // Limitar a 15 ítems para no saturar el DOM
  while (txFeed.children.length > 15) {
    txFeed.removeChild(txFeed.lastChild);
  }
}

/**
 * Actualiza la tabla geográfica con un nuevo dato de IP vs País.
 *
 * TODO: Reemplazar la lógica mock por los datos de:
 *       GET /api/transactions/geo-discrepancies
 *       Variables: IPAddress, ShippingCountry (del dataset pilin.md.txt)
 *
 * @param {Object} tx - Objeto de transacción
 */
function renderGeoTable(tx) {
  // TODO: Inyectar filas dinámicamente en #geo-table-body
  //       Resaltar en naranja si IPCountry != ShippingCountry (Sospechoso)
  //       Resaltar en rojo si la combinación coincide con patrones conocidos de fraude
}

/**
 * Actualiza el Mapa de Calor de unidades de negocio.
 *
 * TODO: Reemplazar datos estáticos del HTML por los de:
 *       GET /api/merchants/fraud-ranking
 *       Agrupar por RUC/Nombre del comercio, ordenar por count descendente.
 *       Calcular el ancho de la barra como (count / maxCount) * 100 + "%"
 */
function renderHeatmap(data) {
  // TODO: Implementar renderizado dinámico en #heatmap-container
}

/**
 * Actualiza la lista de Huella de Identidad (Velocity Check).
 *
 * TODO: Reemplazar los ítems estáticos del HTML por los de:
 *       GET /api/identities/high-risk
 *       Variables: CustomerLegalDocument, CustomerEMail, CustomerPhoneNumber
 *       Mostrar badge si el mismo documento aparece con > 2 tarjetas distintas.
 */
function renderIdentityMonitor(data) {
  // TODO: Implementar renderizado dinámico en #identity-list
}

// ============================================================
// MANEJADOR DE NUEVA TRANSACCIÓN
// ============================================================

/**
 * Punto de entrada principal para procesar cada nueva transacción.
 * Actualiza el estado global y todos los módulos visuales.
 *
 * TODO: Llamar a esta función desde el handler de WebSocket o
 *       desde el polling del backend real.
 *
 * @param {Object} tx - Objeto de transacción (generateMockTransaction o payload real)
 */
function handleNewTransaction(tx) {
  // Actualizar estado global
  state.totalTx++;
  state.totalVolume += tx.TotalValue;

  if (tx._isFraud) {
    state.rejectedTx++;

    // Contar como alerta crítica si es fraude en la última hora
    // TODO: Filtrar por tx.OrderDate — comparar contra (Date.now() - 3600000)
    state.criticalAlerts++;
  }

  // Re-renderizar todos los módulos
  renderKPIs();
  renderTransactionFeed(tx);

  // TODO: Descomentar cuando las funciones estén implementadas:
  // renderGeoTable(tx);
  // renderHeatmap(aggregatedMerchantData);
  // renderIdentityMonitor(aggregatedIdentityData);
}

// ============================================================
// SIMULACIÓN EN TIEMPO REAL (Mock Data Generator Loop)
// ============================================================
// Emite una nueva transacción cada 3 segundos.
// TODO: Eliminar este intervalo cuando se conecte al backend real.
//       Reemplazar por WebSocket o SSE (Server-Sent Events) del endpoint FastAPI.

const SIMULATION_INTERVAL_MS = 3000;

// Cargar 3 transacciones iniciales al abrir el dashboard
for (let i = 0; i < 3; i++) {
  handleNewTransaction(generateMockTransaction());
}

// Luego emitir una nueva cada 3 segundos
setInterval(() => {
  handleNewTransaction(generateMockTransaction());
}, SIMULATION_INTERVAL_MS);

// ============================================================
// FIN — dashboard.js
// Próximos pasos (TODO general):
//  1. Conectar handleNewTransaction() a WebSocket de FastAPI
//  2. Implementar renderGeoTable() con datos reales
//  3. Implementar renderHeatmap() con datos agrupados por RUC
//  4. Implementar renderIdentityMonitor() con velocity checks reales
//  5. Añadir filtros de fecha/rango en el header del dashboard
// ============================================================
