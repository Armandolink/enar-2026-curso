/**
 * Cloud Function: Webhook de Wompi
 * 
 * Recibe notificaciones de pago de Wompi y guarda los pagos aprobados
 * en Firestore para validar registros.
 * 
 * Flujo:
 * 1. Wompi envía POST a esta función cuando una transacción cambia de estado
 * 2. Verificamos la firma (X-Event-Checksum) con el secreto de eventos
 * 3. Si status === "APPROVED", guardamos en colección enar_payments
 * 4. gracias.html verifica que el email tenga pago antes de permitir registro
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

// ── WEBHOOK DE WOMPI ─────────────────────────────────────────
exports.wompiWebhook = functions.https.onRequest(async (req, res) => {
  // Solo acepta POST
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  try {
    const body = req.body;

    // Verificar que es un evento de transacción
    if (!body || !body.event || !body.data || !body.data.transaction) {
      console.warn("Webhook recibido sin datos de transacción:", body);
      return res.status(200).send("OK - ignored");
    }

    const event = body.event;
    const tx = body.data.transaction;

    console.log(`Webhook recibido: ${event}, status: ${tx.status}, ref: ${tx.reference}`);

    // ── Verificar firma (seguridad) ──────────────────────────
    // El secreto de eventos se configura en Firebase config:
    //   firebase functions:config:set wompi.events_secret="tu_secreto"
    const eventsSecret = functions.config().wompi?.events_secret;
    
    if (eventsSecret) {
      const checksum = req.headers["x-event-checksum"];
      if (checksum) {
        // Wompi genera el checksum así:
        // SHA256(transaction.id + transaction.status + transaction.amount_in_cents + events_secret)
        const data = `${tx.id}${tx.status}${tx.amount_in_cents}${eventsSecret}`;
        const expectedChecksum = crypto.createHash("sha256").update(data).digest("hex");
        
        if (checksum !== expectedChecksum) {
          console.error("Firma inválida. Posible fraude.");
          return res.status(200).send("OK - invalid signature");
        }
        console.log("Firma verificada correctamente ✅");
      }
    } else {
      console.warn("⚠️ Sin secreto de eventos configurado. Saltando verificación de firma.");
    }

    // ── Guardar pago en Firestore ────────────────────────────
    const paymentData = {
      transactionId: tx.id || "",
      reference: tx.reference || "",
      status: tx.status || "",
      amountInCents: tx.amount_in_cents || 0,
      currency: tx.currency || "COP",
      customerEmail: (tx.customer_email || "").toLowerCase().trim(),
      paymentMethod: tx.payment_method_type || "",
      paymentLinkId: tx.payment_link_id || null,
      event: event,
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
      raw: JSON.stringify(body),
    };

    // Usar transactionId como doc ID para evitar duplicados
    const docId = tx.id || `manual_${Date.now()}`;
    await db.collection("enar_payments").doc(docId).set(paymentData, { merge: true });

    console.log(`Pago guardado en enar_payments/${docId}`);

    // ── Si fue aprobado, crear entrada de "email autorizado" ─
    if (tx.status === "APPROVED" && tx.customer_email) {
      const email = tx.customer_email.toLowerCase().trim();
      await db.collection("enar_authorized_emails").doc(email).set({
        email: email,
        transactionId: tx.id,
        amount: tx.amount_in_cents,
        approvedAt: admin.firestore.FieldValue.serverTimestamp(),
        used: false,
      }, { merge: true });
      console.log(`Email autorizado: ${email} ✅`);
    }

    return res.status(200).send("OK");
  } catch (error) {
    console.error("Error procesando webhook:", error);
    // Siempre responder 200 para que Wompi no reintente
    return res.status(200).send("OK - error logged");
  }
});
