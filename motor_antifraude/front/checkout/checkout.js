// Lógica principal de formateo, validación y envío simulado del checkout Plux
(function () {
  const form = document.getElementById("checkout-form");
  const cardNumberInput = document.getElementById("card-number");
  const cardExpiryInput = document.getElementById("card-expiry");
  const cardCvcInput = document.getElementById("card-cvc");
  const cardBrandBadge = document.getElementById("card-brand-badge");
  const cardBrandLogo = document.getElementById("card-brand-logo");
  const payButton = document.getElementById("pay-button");
  const payButtonText = document.getElementById("pay-button-text");
  const payButtonLoading = document.getElementById("pay-button-loading");
  const successAlert = document.getElementById("success-alert");

  const subtotalEl = document.getElementById("order-subtotal");
  const taxesEl = document.getElementById("order-taxes");
  const totalEl = document.getElementById("order-total");

  const CARD_LOGOS = {
    visa: "https://1000logos.net/wp-content/uploads/2021/11/VISA-logo-768x432.png",
    mastercard:
      "https://upload.wikimedia.org/wikipedia/commons/0/04/Mastercard-logo.png",
    amex:
      "https://brandemia.org/sites/default/files/inline/images/logo_amex_portada.jpg",
  };

  // --- Helpers de UI ---
  function setButtonLoading(isLoading) {
    if (isLoading) {
      payButton.disabled = true;
      payButton.classList.add("opacity-70", "cursor-not-allowed");
      payButtonText.classList.add("hidden");
      payButtonLoading.classList.remove("hidden");
      payButtonLoading.classList.add("inline-flex");
    } else {
      payButton.disabled = false;
      payButton.classList.remove("opacity-70", "cursor-not-allowed");
      payButtonText.classList.remove("hidden");
      payButtonLoading.classList.add("hidden");
      payButtonLoading.classList.remove("inline-flex");
    }
  }

  function showSuccessMessage() {
    successAlert.classList.remove("hidden");
    successAlert.classList.add("block");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function clearSuccessMessage() {
    successAlert.classList.add("hidden");
    successAlert.classList.remove("block");
  }

  function setFieldError(input, message) {
    const errorEl = document.querySelector(
      '[data-error-for="' + input.id + '"]'
    );
    input.classList.add("border-red-500", "focus:ring-red-500");
    if (errorEl) {
      errorEl.textContent = message || errorEl.textContent;
      errorEl.classList.remove("hidden");
    }
  }

  function clearFieldError(input) {
    const errorEl = document.querySelector(
      '[data-error-for="' + input.id + '"]'
    );
    input.classList.remove("border-red-500", "focus:ring-red-500");
    if (errorEl) {
      errorEl.classList.add("hidden");
    }
  }

  // --- Formateo y detección de marca en tiempo real: número de tarjeta ---
  function detectCardBrandKey(digits) {
    if (!digits || digits.length < 1) return null;

    // Visa: inicia con 4
    if (/^4[0-9]*/.test(digits)) return "visa";
    // Mastercard: rangos 51-55 y 22-27
    if (/^(5[1-5][0-9]*|2[2-7][0-9]*)/.test(digits)) return "mastercard";
    // American Express: 34 o 37
    if (/^3[47][0-9]*/.test(digits)) return "amex";

    return null;
  }

  function getCardBrandLabel(key) {
    switch (key) {
      case "visa":
        return "Visa";
      case "mastercard":
        return "Mastercard";
      case "amex":
        return "American Express";
      default:
        return "Card";
    }
  }

  function updateCardBrandUI(brandKey) {
    if (!brandKey) {
      // Volver al badge genérico
      cardBrandBadge.textContent = "Card";
      cardBrandBadge.classList.remove("hidden");
      if (cardBrandLogo) {
        cardBrandLogo.classList.add("hidden");
        cardBrandLogo.classList.remove("card-brand-logo--visible");
        cardBrandLogo.removeAttribute("src");
        cardBrandLogo.removeAttribute("alt");
      }
      return;
    }

    const logoUrl = CARD_LOGOS[brandKey];
    const label = getCardBrandLabel(brandKey);

    if (logoUrl && cardBrandLogo) {
      cardBrandBadge.classList.add("hidden");
      cardBrandLogo.src = logoUrl;
      cardBrandLogo.alt = label + " logo";
      cardBrandLogo.classList.remove("hidden");
      cardBrandLogo.classList.add("card-brand-logo--visible");
    } else {
      // Fallback al texto si no hay logo
      cardBrandBadge.textContent = label;
      cardBrandBadge.classList.remove("hidden");
      if (cardBrandLogo) {
        cardBrandLogo.classList.add("hidden");
        cardBrandLogo.classList.remove("card-brand-logo--visible");
        cardBrandLogo.removeAttribute("src");
        cardBrandLogo.removeAttribute("alt");
      }
    }
  }

  cardNumberInput.addEventListener("input", function (event) {
    let value = event.target.value || "";
    const digits = value.replace(/\D/g, "").slice(0, 19); // máximo genérico

    const brandKey = detectCardBrandKey(digits);

    let formatted = "";
    if (brandKey === "amex") {
      // Formato típico Amex: 4-6-5
      const part1 = digits.slice(0, 4);
      const part2 = digits.slice(4, 10);
      const part3 = digits.slice(10, 15);
      formatted = [part1, part2, part3].filter(Boolean).join(" ");
    } else {
      const groups = digits.match(/.{1,4}/g) || [];
      formatted = groups.join(" ");
    }

    event.target.value = formatted;
    updateCardBrandUI(brandKey);
  });

  // --- Formateo en tiempo real: expiración MM/YY ---
  cardExpiryInput.addEventListener("input", function (event) {
    let value = event.target.value || "";
    const digits = value.replace(/\D/g, "").slice(0, 4);

    let formatted = digits;
    if (digits.length >= 3) {
      formatted = digits.slice(0, 2) + "/" + digits.slice(2);
    }
    event.target.value = formatted;
  });

  cardExpiryInput.addEventListener("blur", function (event) {
    const value = event.target.value;
    const parts = value.split("/");
    if (parts.length === 2) {
      const month = parseInt(parts[0], 10);
      if (isNaN(month) || month < 1 || month > 12) {
        setFieldError(cardExpiryInput, "Mes inválido. Usa el formato MM/YY.");
        return;
      }
    }
    clearFieldError(cardExpiryInput);
  });

  // --- Formateo en tiempo real: CVC ---
  cardCvcInput.addEventListener("input", function (event) {
    let value = event.target.value || "";
    const digits = value.replace(/\D/g, "").slice(0, 4);
    event.target.value = digits;
  });

  // Limpiar error al escribir en cualquier campo requerido
  form
    .querySelectorAll("[data-required='true']")
    .forEach(function (input) {
      input.addEventListener("input", function () {
        clearFieldError(input);
        clearSuccessMessage();
      });
    });

  // --- Validación mínima de todos los campos requeridos ---
  function validateForm() {
    let isValid = true;
    const requiredInputs = form.querySelectorAll("[data-required='true']");

    requiredInputs.forEach(function (input) {
      const value = input.value.trim();
      if (!value) {
        setFieldError(input, "Este campo es obligatorio.");
        isValid = false;
      } else {
        clearFieldError(input);
      }
    });

    // Validación específica de número de tarjeta
    const cardDigits = cardNumberInput.value.replace(/\D/g, "");
    if (cardDigits.length < 13) {
      setFieldError(
        cardNumberInput,
        "Ingresa un número de tarjeta válido."
      );
      isValid = false;
    }

    // Validación específica de expiración
    const expiryValue = cardExpiryInput.value;
    const parts = expiryValue.split("/");
    if (parts.length !== 2 || parts[0].length !== 2 || parts[1].length !== 2) {
      setFieldError(cardExpiryInput, "Usa el formato MM/YY.");
      isValid = false;
    }

    // Validación específica de CVC
    const cvcDigits = cardCvcInput.value.replace(/\D/g, "");
    if (cvcDigits.length < 3 || cvcDigits.length > 4) {
      setFieldError(cardCvcInput, "Ingresa un CVC válido.");
      isValid = false;
    }

    return isValid;
  }

  // --- Construcción del objeto JSON de checkout ---
  function buildCheckoutPayload() {
    const cardDigits = cardNumberInput.value.replace(/\D/g, "");
    const brandKey = detectCardBrandKey(cardDigits);
    const brandLabel = getCardBrandLabel(brandKey);

    const subtotalText = subtotalEl.textContent.replace(/[^0-9.]/g, "");
    const taxesText = taxesEl.textContent.replace(/[^0-9.]/g, "");
    const totalText = totalEl.textContent.replace(/[^0-9.]/g, "");

    return {
      billing: {
        fullName: document.getElementById("full-name").value.trim(),
        addressLine1: document
          .getElementById("address-line1")
          .value.trim(),
        city: document.getElementById("city").value.trim(),
        state: document.getElementById("state").value.trim(),
        zip: document.getElementById("zip").value.trim(),
      },
      payment: {
        cardName: document.getElementById("card-name").value.trim(),
        cardNumber: cardDigits,
        cardExpiry: cardExpiryInput.value.trim(),
        cardCvc: cardCvcInput.value.trim(),
        cardBrand: brandLabel,
      },
      order: {
        subtotal: parseFloat(subtotalText) || 0,
        taxes: parseFloat(taxesText) || 0,
        total: parseFloat(totalText) || 0,
        currency: "USD",
      },
      meta: {
        source: "plux-checkout",
        createdAt: new Date().toISOString(),
      },
    };
  }

  // --- Manejo del envío del formulario (simulado) ---
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    clearSuccessMessage();

    if (!validateForm()) {
      console.warn("Checkout Plux: formulario inválido.");
      return;
    }

    const payload = buildCheckoutPayload();
    console.log(
      "Payload listo para enviar al motor antifraude:",
      payload
    );
    console.log("Payload JSON:", JSON.stringify(payload, null, 2));

    setButtonLoading(true);

    // Simulación de llamada al motor antifraude / pasarela
    setTimeout(function () {
      setButtonLoading(false);
      showSuccessMessage();

      // Simulación de redirección
      setTimeout(function () {
        console.log("Redirigiendo al comercio de origen...");
      }, 1200);
    }, 1800);
  });
})();

