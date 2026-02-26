// register.js — Lógica de registro para Plux
// POST /v1/auth/register — Content-Type: multipart/form-data (via FormData)
//
// ⚠️ IMPORTANTE: NO se añade el header 'Content-Type' manualmente.
// El navegador lo añade automáticamente con el boundary correcto
// cuando el body es un objeto FormData.

const API_BASE = 'http://localhost:8000';

// ── Elementos DOM ─────────────────────────────────────────────────────────────
const form = document.getElementById('register-form');
const step1El = document.getElementById('step-1');
const step2El = document.getElementById('step-2');
const dot1 = document.getElementById('dot-1');
const dot2 = document.getElementById('dot-2');
const btnNext = document.getElementById('btn-step-next');
const btnBack = document.getElementById('btn-step-back');
const submitBtn = document.getElementById('submit-btn');
const btnText = document.getElementById('btn-text');
const btnSpinner = document.getElementById('btn-spinner');
const errorMsg = document.getElementById('error-msg');
const errorText = document.getElementById('error-text');
const togglePass = document.getElementById('toggle-pass');

// Indicadores de paso en el panel lateral
const stepInd1 = document.getElementById('step-indicator-1');
const stepInd2 = document.getElementById('step-indicator-2');

// Títulos del formulario
const stepTitle = document.getElementById('step-title');
const stepSubtitle = document.getElementById('step-subtitle');

// Campos
const emailInput = document.getElementById('email');
const usernameInput = document.getElementById('username');
const passInput = document.getElementById('password');
const cedulaInput = document.getElementById('cedula');

// Errores de campo
const errEmail = document.getElementById('err-email');
const errUsername = document.getElementById('err-username');
const errPassword = document.getElementById('err-password');
const errCedula = document.getElementById('err-cedula');

// Barras de fuerza de contraseña
const bars = [
    document.getElementById('bar-1'),
    document.getElementById('bar-2'),
    document.getElementById('bar-3'),
    document.getElementById('bar-4'),
];

// ── Toast system ──────────────────────────────────────────────────────────────
function createToastContainer() {
    let tc = document.getElementById('toast-container');
    if (!tc) {
        tc = document.createElement('div');
        tc.id = 'toast-container';
        tc.style.cssText = [
            'position:fixed',
            'top:20px',
            'right:20px',
            'z-index:9999',
            'display:flex',
            'flex-direction:column',
            'gap:10px',
            'pointer-events:none',
        ].join(';');
        document.body.appendChild(tc);
    }
    return tc;
}

function showToast(message, type = 'error') {
    const container = createToastContainer();
    const colors = {
        error: { bg: '#fef2f2', border: '#fca5a5', text: '#b91c1c', icon: '#ef4444', svg: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>' },
        success: { bg: '#f0fdf4', border: '#86efac', text: '#166534', icon: '#22c55e', svg: '<polyline points="20 6 9 17 4 12"/>' },
        warning: { bg: '#fffbeb', border: '#fcd34d', text: '#92400e', icon: '#f59e0b', svg: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>' },
    };
    const c = colors[type] || colors.error;
    const toast = document.createElement('div');
    toast.style.cssText = [
        `background:${c.bg}`, `border:1.5px solid ${c.border}`, `color:${c.text}`,
        'border-radius:14px', 'padding:14px 18px', 'display:flex', 'align-items:center',
        'gap:12px', 'font-size:14px', 'font-weight:600', 'font-family:Inter,sans-serif',
        'box-shadow:0 8px 30px rgba(0,0,0,0.12)', 'pointer-events:all', 'cursor:pointer',
        'max-width:360px', 'transition:opacity 0.3s,transform 0.3s',
        'opacity:0', 'transform:translateX(20px)',
    ].join(';');
    toast.innerHTML = `
        <svg style="flex-shrink:0;" width="18" height="18" fill="none" stroke="${c.icon}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">${c.svg}</svg>
        <span style="flex:1;">${message}</span>
        <svg style="flex-shrink:0;opacity:0.5;" width="14" height="14" fill="none" stroke="${c.text}" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    `;
    container.appendChild(toast);
    requestAnimationFrame(() => requestAnimationFrame(() => { toast.style.opacity = '1'; toast.style.transform = 'translateX(0)'; }));
    toast.addEventListener('click', () => dismissToast(toast));
    toast._timer = setTimeout(() => dismissToast(toast), 4500);
    return toast;
}

function dismissToast(toast) {
    clearTimeout(toast._timer);
    toast.style.opacity = '0'; toast.style.transform = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
}

// ── Toggle visibilidad de contraseña ─────────────────────────────────────────
togglePass.addEventListener('click', () => {
    const isPass = passInput.type === 'password';
    passInput.type = isPass ? 'text' : 'password';
    togglePass.innerHTML = isPass
        ? `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
               <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
               <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
               <line x1="1" y1="1" x2="23" y2="23"/>
           </svg>`
        : `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
               <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
               <circle cx="12" cy="12" r="3"/>
           </svg>`;
});

// ── Indicador de fuerza de contraseña ────────────────────────────────────────
const strengthColors = ['#f87171', '#fb923c', '#facc15', '#22c55e'];

passInput.addEventListener('input', () => {
    const val = passInput.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    bars.forEach((bar, i) => {
        if (bar) {
            bar.style.background = (i < score) ? strengthColors[score - 1] : '#e5e7eb';
        }
    });
});

// ── Utilidades UI ─────────────────────────────────────────────────────────────
function showError(msg) {
    errorText.textContent = msg;
    errorMsg.style.display = 'flex';
    errorMsg.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideError() {
    errorMsg.style.display = 'none';
}

function setFieldError(errEl, inputEl, show) {
    if (!errEl || !inputEl) return;
    errEl.style.display = show ? 'block' : 'none';
    if (show) {
        inputEl.style.borderColor = '#f87171';
        inputEl.style.boxShadow = '0 0 0 4px rgba(248,113,113,0.1)';
    } else {
        inputEl.style.borderColor = '';
        inputEl.style.boxShadow = '';
    }
}

function setLoading(loading) {
    submitBtn.disabled = loading;
    btnText.textContent = loading ? 'Creando cuenta…' : 'Crear Cuenta';
    btnSpinner.style.display = loading ? 'block' : 'none';
}

// ── Navegación entre pasos ────────────────────────────────────────────────────
function goToStep(step) {
    if (step === 1) {
        step1El.style.display = 'flex';
        step2El.style.display = 'none';

        // Dots
        dot1.style.width = '24px';
        dot1.style.background = '#7c3aed';
        dot1.style.borderRadius = '99px';
        dot2.style.width = '8px';
        dot2.style.background = '#e5e7eb';
        dot2.style.borderRadius = '50%';

        // Texto
        if (stepTitle) stepTitle.textContent = 'Crea tu cuenta';
        if (stepSubtitle) stepSubtitle.textContent = 'Empecemos con tus datos básicos.';

        // Panel lateral
        if (stepInd1) stepInd1.style.opacity = '1';
        if (stepInd2) stepInd2.style.opacity = '0.5';

    } else {
        step1El.style.display = 'none';
        step2El.style.display = 'flex';

        // Dots
        dot1.style.width = '8px';
        dot1.style.background = '#7c3aed';
        dot1.style.borderRadius = '50%';
        dot2.style.width = '24px';
        dot2.style.background = '#7c3aed';
        dot2.style.borderRadius = '99px';

        // Texto
        if (stepTitle) stepTitle.textContent = 'Verifica tu identidad';
        if (stepSubtitle) stepSubtitle.textContent = 'Ingresa tu número de cédula.';

        // Panel lateral
        if (stepInd1) stepInd1.style.opacity = '0.6';
        if (stepInd2) stepInd2.style.opacity = '1';

        if (cedulaInput) cedulaInput.focus();
    }
}

btnBack.addEventListener('click', () => {
    hideError();
    goToStep(1);
});

// ── Validación paso 1 ─────────────────────────────────────────────────────────
function validateStep1() {
    let valid = true;

    const email = emailInput.value.trim();
    const username = usernameInput.value.trim();
    const password = passInput.value;

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    setFieldError(errEmail, emailInput, !emailOk);
    if (!emailOk) valid = false;

    const usernameOk = username.length >= 3 && username.length <= 50 && /^[a-zA-Z0-9_-]+$/.test(username);
    setFieldError(errUsername, usernameInput, !usernameOk);
    if (!usernameOk) valid = false;

    // El backend exige: mín 8 chars, una mayúscula, una minúscula, un número
    const passOk = password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
    setFieldError(errPassword, passInput, !passOk);
    if (!passOk) {
        if (password.length > 0 && !passOk) {
            showToast('La contraseña debe tener mínimo 8 caracteres, una mayúscula y un número.', 'warning');
        }
        valid = false;
    }

    return valid;
}

// ── Validación paso 2 ─────────────────────────────────────────────────────────
function validateStep2() {
    const cedula = cedulaInput.value.trim();
    const cedulaOk = /^\d{6,20}$/.test(cedula);
    setFieldError(errCedula, cedulaInput, !cedulaOk);
    return cedulaOk;
}

// ── Botón "Siguiente" ─────────────────────────────────────────────────────────
btnNext.addEventListener('click', () => {
    hideError();
    if (validateStep1()) {
        goToStep(2);
    }
});

// ── Submit — POST /v1/auth/register ──────────────────────────────────────────
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    if (!validateStep2()) return;

    const email = emailInput.value.trim();
    const username = usernameInput.value.trim();
    const password = passInput.value;
    const cedula = cedulaInput.value.trim();

    // Construir FormData — SIN face_photo (es Optional en el backend)
    const formData = new FormData();
    formData.append('email', email);
    formData.append('username', username);
    formData.append('password', password);
    formData.append('cedula', cedula);

    setLoading(true);

    try {
        const response = await fetch(`${API_BASE}/v1/auth/register`, {
            method: 'POST',
            headers: { 'Accept': 'application/json' },
            body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
            let msg = 'Error al crear la cuenta.';
            if (typeof data?.detail === 'string') {
                msg = data.detail;
            } else if (Array.isArray(data?.detail) && data.detail[0]?.msg) {
                // Pydantic validation errors
                msg = data.detail.map(e => e.msg.replace('Value error, ', '')).join(' · ');
            }
            showError(msg);
            showToast(msg, 'error');
            return;
        }

        // ── Éxito (201) → redirigir a login con indicador ────────────────────
        console.log('[Plux Register] Cuenta creada:', data);
        sessionStorage.setItem('plux_registered', '1');
        showToast('¡Cuenta creada exitosamente!', 'success');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 700);

    } catch (err) {
        console.error('[Plux Register] Error de red:', err);
        const msg = 'No se pudo conectar con el servidor. Verifica que el backend esté activo.';
        showError(msg);
        showToast(msg, 'error');
    } finally {
        setLoading(false);
    }
});

// ── Limpiar errores al tipear ─────────────────────────────────────────────────
emailInput?.addEventListener('input', () => setFieldError(errEmail, emailInput, false));
usernameInput?.addEventListener('input', () => setFieldError(errUsername, usernameInput, false));
passInput?.addEventListener('input', () => setFieldError(errPassword, passInput, false));
cedulaInput?.addEventListener('input', () => setFieldError(errCedula, cedulaInput, false));
