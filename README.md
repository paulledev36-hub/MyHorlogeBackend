# MyHorloge — Backend sécurisé BYOK (Vercel & Google Cloud Run)

Ce service garantit que les clés API Gemini personnelles des utilisateurs **ne quittent jamais le backend** lors des requêtes vers Google AI Studio :

1. L'application Android envoie la clé personnelle **une seule fois** sur `POST /byok/key` en HTTPS avec `Authorization: Bearer <Firebase ID Token>`.
2. Le serveur vérifie le Firebase ID Token (`firebase-admin` Auth), dérive une sous-clé par `uid` via HKDF-SHA256 et chiffre la clé API avec **AES-256-GCM** (`AAD = uid`) avant écriture dans Firestore (collection serveur `byok_vault_encrypted`) — ou dans Google Cloud Secret Manager. Aucune clé en clair n'est écrite dans Firestore ni dans les logs.
3. Lors des appels `POST /byok/generate`, `POST /byok/test`, `GET /byok/models` et `DELETE /byok/key`, Android envoie uniquement le Firebase ID Token.

Le même dossier fonctionne **sans changer Android** sur **Vercel** (gratuit sans carte bancaire) et sur **Google Cloud Run**.

---

## Variables d'environnement et secrets

| Nom | Vercel (obligatoire ?) | Cloud Run (obligatoire ?) | Valeur pour ce projet |
|---|---|---|---|
| `GOOGLE_CLOUD_PROJECT` | Recommandé | Recommandé | `gen-lang-client-0987408187` |
| `BYOK_STORAGE_MODE` | `firestore-encrypted` | `firestore-encrypted` | `firestore-encrypted` |
| `FIRESTORE_DATABASE_ID` | **Obligatoire** | **Obligatoire** | `ai-studio-android-myhorlog-d8ba217e-6e58-45bc-8987-2b39682ec708` |
| `BYOK_FIRESTORE_COLLECTION` | Optionnel | Optionnel | `byok_vault_encrypted` |
| `BYOK_VAULT_MASTER_KEY` | **Obligatoire** (Secret) | **Obligatoire** (Secret Manager) | Clé hex 64 caractères (32 octets aléatoires) |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | **Obligatoire** (Secret) | Non nécessaire (IAM natif) | Contenu du fichier JSON de compte de service Firebase |

---

## Option 1 — Déploiement gratuit sur Vercel (sans carte bancaire)

1. Créez un dépôt GitHub **privé** contenant uniquement le contenu de `backend/byok-server` (ou importez le dépôt complet en réglant **Root Directory = `backend/byok-server`** sur Vercel).
2. Dans la console Firebase (**Paramètres du projet → Comptes de service → Générer une nouvelle clé privée**), téléchargez le JSON du compte de service.
3. Générez localement une clé maître aléatoire (`openssl rand -hex 32` ou générateur 64 hex) sans jamais la committer sur GitHub.
4. Sur Vercel (**Project Settings → Environment Variables**), ajoutez en *Production* :
   - `GOOGLE_CLOUD_PROJECT` = `gen-lang-client-0987408187`
   - `BYOK_STORAGE_MODE` = `firestore-encrypted`
   - `FIRESTORE_DATABASE_ID` = `ai-studio-android-myhorlog-d8ba217e-6e58-45bc-8987-2b39682ec708`
   - `BYOK_FIRESTORE_COLLECTION` = `byok_vault_encrypted`
   - `BYOK_VAULT_MASTER_KEY` = *(votre clé hex 64 caractères)*
   - `FIREBASE_SERVICE_ACCOUNT_JSON` = *(le contenu complet du fichier JSON Firebase téléchargé)*
5. Déployez sur Vercel, vérifiez `https://<votre-projet>.vercel.app/healthz` (`{"status":"ok"}`), puis collez `https://<votre-projet>.vercel.app` dans **MyHorloge → Réglages → Assistant IA → URL HTTPS du backend sécurisé BYOK**.

---

## Option 2 — Déploiement sur Google Cloud Run

```bash
gcloud config set project gen-lang-client-0987408187

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  firestore.googleapis.com \
  identitytoolkit.googleapis.com

gcloud iam service-accounts create myhorloge-byok-sa \
  --display-name="MyHorloge BYOK Backend"

openssl rand -hex 32 | gcloud secrets create myhorloge-byok-master-key --data-file=-

gcloud secrets add-iam-policy-binding myhorloge-byok-master-key \
  --member="serviceAccount:myhorloge-byok-sa@gen-lang-client-0987408187.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding gen-lang-client-0987408187 \
  --member="serviceAccount:myhorloge-byok-sa@gen-lang-client-0987408187.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

cd backend/byok-server
gcloud run deploy myhorloge-byok \
  --source . \
  --region europe-west1 \
  --service-account myhorloge-byok-sa@gen-lang-client-0987408187.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=gen-lang-client-0987408187,BYOK_STORAGE_MODE=firestore-encrypted,BYOK_FIRESTORE_COLLECTION=byok_vault_encrypted,FIRESTORE_DATABASE_ID=ai-studio-android-myhorlog-d8ba217e-6e58-45bc-8987-2b39682ec708" \
  --set-secrets "BYOK_VAULT_MASTER_KEY=myhorloge-byok-master-key:latest"
```

---

## Tests locaux

```bash
node --test server.test.js
```
