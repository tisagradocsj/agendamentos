const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
admin.initializeApp();

// Permite que um administrador (documento em admins/<email>) defina ou troque a senha de qualquer usuário cadastrado.
exports.setUserPassword = onCall({ region: "southamerica-east1" }, async (req) => {
  const caller = (req.auth?.token?.email || "").toLowerCase();
  if (!caller) throw new HttpsError("unauthenticated", "Faça login novamente.");
  const isAdmin = (await admin.firestore().doc(`admins/${caller}`).get()).exists;
  if (!isAdmin) throw new HttpsError("permission-denied", "Apenas administradores podem alterar senhas.");

  const target = String(req.data?.email || "").trim().toLowerCase();
  const password = String(req.data?.password || "");
  if (!/^\S+@\S+\.\S+$/.test(target)) throw new HttpsError("invalid-argument", "E-mail inválido.");
  if (password.length < 6) throw new HttpsError("invalid-argument", "A senha precisa ter pelo menos 6 caracteres.");
  if (!(await admin.firestore().doc(`teachers/${target}`).get()).exists)
    throw new HttpsError("not-found", "Usuário não cadastrado.");

  try {
    const u = await admin.auth().getUserByEmail(target);
    await admin.auth().updateUser(u.uid, { password });
    return { created: false };
  } catch (e) {
    if (e.code === "auth/user-not-found") {
      await admin.auth().createUser({ email: target, password });
      return { created: true };
    }
    throw new HttpsError("internal", e.message);
  }
});
