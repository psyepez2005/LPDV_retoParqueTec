// auth.js - Lógica de Registro y KYC para Plux

let registrationData = {
    email: "",
    phone: "",
    password: "",
    id_number: "",
    id_photo: null,
    selfie_photo: null
};

// --- NAVEGACIÓN ---
function nextStep(current, next) {
    document.getElementById(`step${current}`).classList.add("hidden");
    document.getElementById(`step${next}`).classList.remove("hidden");
    
    // Si entramos a pasos de cámara, activarla
    if (next === 2) startCamera("videoID");
    if (next === 3) startCamera("videoSelfie");
}

// --- LÓGICA DE CÁMARA ---
async function startCamera(videoElementId) {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        const video = document.getElementById(videoElementId);
        video.srcObject = stream;
    } catch (err) {
        console.error("Error al acceder a la cámara:", err);
        alert("Necesitas permitir la cámara para validar tu identidad.");
    }
}

function capture(type, nextStepNum) {
    const videoId = type === 'id' ? 'videoID' : 'videoSelfie';
    const video = document.getElementById(videoId);
    const canvas = document.createElement("canvas");
    
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext("2d").drawImage(video, 0, 0);
    
    const photoBase64 = canvas.toDataURL("image/png");
    
    if (type === 'id') registrationData.id_photo = photoBase64;
    else registrationData.selfie_photo = photoBase64;

    nextStep(nextStepNum - 1, nextStepNum);
}

// --- ENVÍO AL BACKEND ---
async function finishRegistration() {
    // Capturamos los datos finales del form
    registrationData.email = document.getElementById("email").value;
    registrationData.phone = document.getElementById("phone").value;
    registrationData.id_number = document.getElementById("id_num").value;

    console.log("Enviando datos a FastAPI...", registrationData);

    try {
        const response = await fetch("http://localhost:8000/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(registrationData)
        });

        if (response.ok) {
            alert("¡Registro exitoso!");
            // Aquí podrías mostrar el panel de análisis que tienes en app.js
            document.getElementById("step4").classList.remove("hidden");
            document.getElementById("dashboard").classList.remove("hidden");
        }
    } catch (error) {
        console.error("Error en el registro:", error);
    }
}