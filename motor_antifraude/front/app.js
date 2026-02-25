// Referencias a elementos del DOM
const analyzeButton = document.getElementById("analyzeButton");
const scenarioSelect = document.getElementById("scenarioSelect");
const payloadInput = document.getElementById("payloadInput");

const stateInitial = document.getElementById("stateInitial");
const stateLoading = document.getElementById("stateLoading");
const stateResult = document.getElementById("stateResult");

const scoreValue = document.getElementById("scoreValue");
const scoreBar = document.getElementById("scoreBar");
const verdictAlert = document.getElementById("verdictAlert");
const verdictTitle = document.getElementById("verdictTitle");
const verdictMessage = document.getElementById("verdictMessage");
const verdictChip = document.getElementById("verdictChip");

// Clases Tailwind que iremos cambiando según el score
const TEXT_COLOR_CLASSES = ["text-emerald-600", "text-yellow-600", "text-red-600"];
const BAR_COLOR_CLASSES = ["bg-emerald-500", "bg-yellow-500", "bg-red-600"];
const ALERT_BG_CLASSES = ["bg-emerald-50", "bg-yellow-50", "bg-red-50"];
const ALERT_BORDER_CLASSES = ["border-emerald-500", "border-yellow-500", "border-red-600"];
const ALERT_TEXT_TITLE_CLASSES = [
  "text-emerald-700",
  "text-yellow-700",
  "text-red-700"
];
const CHIP_BG_CLASSES = ["bg-emerald-50", "bg-yellow-50", "bg-red-50"];
const CHIP_TEXT_CLASSES = ["text-emerald-700", "text-yellow-700", "text-red-700"];
const CHIP_BORDER_CLASSES = [
  "border-emerald-200",
  "border-yellow-200",
  "border-red-200"
];

// Maneja el clic en "Ejecutar Análisis de Riesgo"
analyzeButton.addEventListener("click", () => {
  const rawPayload = payloadInput.value.trim();
  const scenario = scenarioSelect.value;

  // Intento opcional de parseo, para mostrar cómo se podría enviar a FastAPI.
  let parsedPayload = null;
  if (rawPayload) {
    try {
      parsedPayload = JSON.parse(rawPayload);
    } catch (error) {
      console.warn("JSON inválido. En la demo no se rompe la UI.", error);
    }
  }

  // En este punto es donde conectarías con FastAPI.
  // Ejemplo orientativo (comentado):
  //
  // fetch("http://localhost:8000/analizar-riesgo", {
  //   method: "POST",
  //   headers: {
  //     "Content-Type": "application/json"
  //   },
  //   body: JSON.stringify(parsedPayload || { raw: rawPayload })
  // })
  //   .then((res) => res.json())
  //   .then((data) => {
  //     const score = data.score;
  //     showResultState(score);
  //   })
  //   .catch((err) => {
  //     console.error("Error llamando a FastAPI", err);
  //   });

  // Para la demo, generamos el score en front según el escenario forzado.
  const simulatedScore = generateScoreByScenario(scenario);

  // Simulamos latencia de red de 1.5s
  showLoadingState();
  setButtonLoading(true);

  setTimeout(() => {
    showResultState(simulatedScore);
    setButtonLoading(false);
  }, 1500);
});

/**
 * Genera un score aleatorio según el escenario seleccionado.
 */
function generateScoreByScenario(scenario) {
  switch (scenario) {
    case "approved":
      // 0 a 20
      return getRandomIntInclusive(0, 20);
    case "suspicious":
      // 21 a 69
      return getRandomIntInclusive(21, 69);
    case "fraud":
      // 70 a 100
      return getRandomIntInclusive(70, 100);
    case "random":
    default:
      // 0 a 100
      return getRandomIntInclusive(0, 100);
  }
}

/**
 * Número entero aleatorio entre min y max (ambos inclusive).
 */
function getRandomIntInclusive(min, max) {
  const minCeil = Math.ceil(min);
  const maxFloor = Math.floor(max);
  return Math.floor(Math.random() * (maxFloor - minCeil + 1)) + minCeil;
}

/**
 * Muestra el estado de carga (skeleton / spinner).
 */
function showLoadingState() {
  stateInitial.classList.add("hidden");
  stateResult.classList.add("hidden");
  stateLoading.classList.remove("hidden");
}

/**
 * Muestra el estado de resultado y aplica la lógica de negocio visual.
 */
function showResultState(score) {
  // Ocultamos estados previos
  stateInitial.classList.add("hidden");
  stateLoading.classList.add("hidden");
  stateResult.classList.remove("hidden");

  // Mostramos el score numérico
  scoreValue.textContent = String(score);
  scoreBar.style.width = `${score}%`;

  // Determinamos el índice de color según la regla de negocio
  // 0 – 20: verde
  // 21 – 69: amarillo/naranja
  // 70 – 100: rojo
  let colorIndex = 0; // 0 = verde, 1 = amarillo, 2 = rojo
  if (score <= 20) {
    colorIndex = 0;
  } else if (score <= 69) {
    colorIndex = 1;
  } else {
    colorIndex = 2;
  }

  applyColorScheme(colorIndex);

  // Mensajes según el rango
  if (colorIndex === 0) {
    // Aprobado
    verdictTitle.textContent = "Aprobada - Transacción Segura";
    verdictMessage.textContent =
      "Pasa directa sin problemas. El score de riesgo es bajo y el patrón de uso es consistente.";
    verdictChip.textContent = "Aprobada";
  } else if (colorIndex === 1) {
    // Sospechosa
    verdictTitle.textContent = "Sospechosa - Requiere Validación Secundaria";
    verdictMessage.textContent =
      "Se recomienda verificación adicional (OTP, challenge, documentación) antes de liberar los fondos.";
    verdictChip.textContent = "Sospechosa";
  } else {
    // Fraude
    verdictTitle.textContent = "Rechazada - Fraude Directo";
    verdictMessage.textContent =
      "El patrón coincide con intentos de fraude conocidos. Bloquear y escalar al área de investigaciones.";
    verdictChip.textContent = "Fraude";
  }
}

/**
 * Aplica todas las clases de color según el índice elegido (0=verde, 1=amarillo, 2=rojo).
 */
function applyColorScheme(index) {
  // Limpiamos clases previas
  TEXT_COLOR_CLASSES.forEach((cls) => scoreValue.classList.remove(cls));
  BAR_COLOR_CLASSES.forEach((cls) => scoreBar.classList.remove(cls));
  ALERT_BG_CLASSES.forEach((cls) => verdictAlert.classList.remove(cls));
  ALERT_BORDER_CLASSES.forEach((cls) => verdictAlert.classList.remove(cls));
  ALERT_TEXT_TITLE_CLASSES.forEach((cls) => verdictTitle.classList.remove(cls));
  CHIP_BG_CLASSES.forEach((cls) => verdictChip.classList.remove(cls));
  CHIP_TEXT_CLASSES.forEach((cls) => verdictChip.classList.remove(cls));
  CHIP_BORDER_CLASSES.forEach((cls) => verdictChip.classList.remove(cls));

  // Aplicamos las nuevas
  scoreValue.classList.add(TEXT_COLOR_CLASSES[index]);
  scoreBar.classList.add(BAR_COLOR_CLASSES[index]);
  verdictAlert.classList.add(ALERT_BG_CLASSES[index], ALERT_BORDER_CLASSES[index]);
  verdictTitle.classList.add(ALERT_TEXT_TITLE_CLASSES[index]);
  verdictChip.classList.add(
    CHIP_BG_CLASSES[index],
    CHIP_TEXT_CLASSES[index],
    CHIP_BORDER_CLASSES[index]
  );
}

/**
 * Marca o desmarca el botón principal como "cargando".
 */
function setButtonLoading(isLoading) {
  if (isLoading) {
    analyzeButton.disabled = true;
    analyzeButton.classList.add("opacity-70", "cursor-wait");
    analyzeButton.textContent = "Analizando...";
  } else {
    analyzeButton.disabled = false;
    analyzeButton.classList.remove("opacity-70", "cursor-wait");
    analyzeButton.textContent = "Ejecutar Análisis de Riesgo";
  }
}