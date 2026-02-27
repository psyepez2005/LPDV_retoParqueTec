// login.js — Lógica de inicio de sesión para Plux
// POST /v1/auth/login — Content-Type: application/json

const API_BASE = 'https://motor-antifraude-api.onrender.com';

// ── Elementos DOM ─────────────────────────────────────────────────────────────
const form = document.getElementById('login-form');
const emailInput = document.getElementById('email');
const passInput = document.getElementById('password');
const submitBtn = document.getElementById('submit-btn');
const btnText = document.getElementById('btn-text');
const btnSpinner = document.getElementById('btn-spinner');
const errorMsg = document.getElementById('error-msg');
const errorText = document.getElementById('error-text');
const successMsg = document.getElementById('success-msg');
const togglePass = document.getElementById('toggle-pass');

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
        `background:${c.bg}`,
        `border:1.5px solid ${c.border}`,
        `color:${c.text}`,
        'border-radius:14px',
        'padding:14px 18px',
        'display:flex',
        'align-items:center',
        'gap:12px',
        'font-size:14px',
        'font-weight:600',
        'font-family:Inter,sans-serif',
        'box-shadow:0 8px 30px rgba(0,0,0,0.12)',
        'pointer-events:all',
        'cursor:pointer',
        'max-width:360px',
        'transition:opacity 0.3s,transform 0.3s',
        'opacity:0',
        'transform:translateX(20px)',
    ].join(';');

    toast.innerHTML = `
        <svg style="flex-shrink:0;" width="18" height="18" fill="none" stroke="${c.icon}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">${c.svg}</svg>
        <span style="flex:1;">${message}</span>
        <svg style="flex-shrink:0;opacity:0.5;" width="14" height="14" fill="none" stroke="${c.text}" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    `;

    container.appendChild(toast);

    // Animación entrada
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateX(0)';
        });
    });

    // Cerrar al hacer clic
    toast.addEventListener('click', () => dismissToast(toast));

    // Auto-cerrar en 4s
    const timer = setTimeout(() => dismissToast(toast), 4000);
    toast._timer = timer;

    return toast;
}

function dismissToast(toast) {
    clearTimeout(toast._timer);
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
}

// ── Mostrar mensaje de éxito si viene desde registro ─────────────────────────
window.addEventListener('DOMContentLoaded', () => {
    if (sessionStorage.getItem('plux_registered') === '1') {
        successMsg.style.display = 'flex';
        sessionStorage.removeItem('plux_registered');
        showToast('¡Cuenta creada con éxito! Inicia sesión.', 'success');
    }
});

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

// ── Utilidades UI ─────────────────────────────────────────────────────────────
function showError(msg) {
    errorText.textContent = msg;
    errorMsg.style.display = 'flex';
}

function hideError() {
    errorMsg.style.display = 'none';
}

function setLoading(loading) {
    submitBtn.disabled = loading;
    btnText.textContent = loading ? 'Verificando…' : 'Iniciar Sesión';
    btnSpinner.style.display = loading ? 'block' : 'none';
}

// ── Validación básica ─────────────────────────────────────────────────────────
function validate() {
    const email = emailInput.value.trim();
    const password = passInput.value;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showError('Ingresa un correo electrónico válido.');
        emailInput.focus();
        return false;
    }
    if (!password) {
        showError('La contraseña no puede estar vacía.');
        passInput.focus();
        return false;
    }
    return true;
}

// ── Submit — POST /v1/auth/login ──────────────────────────────────────────────
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    if (!validate()) return;

    const email = emailInput.value.trim();
    const password = passInput.value;

    setLoading(true);

    try {
        const response = await fetch(`${API_BASE}/v1/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (!response.ok) {
            const msg = data?.detail || 'Credenciales incorrectas.';

            // Toast popup visible
            showToast('🔒 ' + msg, 'error');

            // También el mensaje inline
            showError(msg);
            return;
        }

        // ── Éxito: guardar token y redirigir ─────────────────────────────────
        if (data.access_token) {
            localStorage.setItem('plux_token', data.access_token);
            localStorage.setItem('plux_user_id', data.user_id || '');
        }

        showToast('¡Bienvenido a Plux!', 'success');

        // Pequeño delay para que el toast sea visible antes del redirect
        setTimeout(() => {
            window.location.href = '../motor/index.html';
        }, 600);

    } catch (err) {
        console.error('[Plux Login] Error de red:', err);
        const msg = 'No se pudo conectar con el servidor. Verifica que el backend esté activo.';
        showToast(msg, 'error');
        showError(msg);
    } finally {
        setLoading(false);
    }
});

// ── Limpiar error al tipear ───────────────────────────────────────────────────
[emailInput, passInput].forEach(el => el.addEventListener('input', hideError));
