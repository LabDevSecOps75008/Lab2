# Lab 2 — SAST avec Semgrep

**Durée : 1h30** &nbsp;|&nbsp; **Stack : PHP 8.2** &nbsp;|&nbsp; **Outil : Semgrep**

---

## Contexte

L'API `freemobile-netops-api` est une application PHP interne qui gère les équipements réseau du NOC (Network Operations Center). Elle s'apprête à passer en production.

Un audit **SAST (Static Application Security Testing)** est requis avant le déploiement.

> **SAST vs DAST en une phrase**
> Le SAST analyse le **code source sans l'exécuter** — comme une relecture de code automatisée orientée sécurité. Le DAST teste l'application **en cours d'exécution** en envoyant de vraies requêtes. L'un détecte les vulnérabilités à l'écriture, l'autre à l'exécution.

---

## Prérequis : un seul outil

| Outil | Vérification |
|-------|-------------|
| Docker | `docker --version` |

> L'application **et** Semgrep tournent tous les deux dans Docker.  
> Pas de PHP à installer. Pas de Python. Pas de problème de version.

---

## Structure du projet

```
Lab2/
├── index.php                      ← API PHP avec 5 vulnérabilités intentionnelles
├── docker-compose.yml             ← PHP 8.2 CLI
├── .github/
│   └── workflows/
│       └── security.yml           ← Pipeline CI à compléter (Étape 3)
└── solution/
    ├── index.php                  ← Code corrigé (ne pas consulter avant l'Étape 4)
    └── security.yml               ← Pipeline CI complète
```

---

## Comment lire une alerte Semgrep

Avant de lancer le scan, voici comment décoder un résultat. Cette section vous évitera de vous perdre dans la sortie.

**Exemple de finding :**

```
index.php
  ❯❯❱ php.lang.security.eval-use   [ERROR]
      eval() avec entrée utilisateur non filtrée : risque d'exécution
      de code arbitraire (RCE).

      Details: https://sg.run/xxxxx

      ▶  146 ┆     $result = eval("return $rule;");
```

**Décodage ligne par ligne :**

| Élément | Signification |
|---------|--------------|
| `index.php` | Fichier analysé |
| `php.lang.security.eval-use` | **Identifiant de règle** — unique, cherchable sur [semgrep.dev/r/](https://semgrep.dev/r/) |
| `[ERROR]` | **Sévérité** : voir tableau ci-dessous |
| Message | Explication en langage naturel de la vulnérabilité |
| `146 ┆` | Numéro de ligne dans le code source |
| URL Details | Documentation complète + exemples de correction |

**Les 3 niveaux de sévérité :**

| Sévérité | Icône | Effet avec `--error` | Quand l'utiliser |
|----------|-------|---------------------|-----------------|
| `ERROR`  | ❯❯❱  | **La CI échoue**     | Vulnérabilités critiques à bloquer |
| `WARNING`| ❯❯⚠  | La CI passe          | Points à revoir, non bloquants |
| `INFO`   | ❯❯ℹ  | La CI passe          | Bonnes pratiques |

**Résumé affiché en fin de scan :**

```
Ran 52 rules on 1 file: 6 findings.
```

- `Exit code 0` → aucun finding (ou `--error` non utilisé)
- `Exit code 1` → finding(s) ERROR détecté(s) avec `--error` → **la CI échoue**

---

## Étape 0 — Démarrer l'API

```bash
docker compose up -d
curl http://localhost:8080/health
# → {"status":"ok","service":"freemobile-netops-api-php"}
```

---

## Étape 1 — Premier scan SAST

**Avec Docker (recommandé) :**

```bash
docker run --rm \
  -v "$(pwd):/src" \
  semgrep/semgrep \
  semgrep --config p/php --error /src/index.php

echo "Exit code: $?"
```

> **Si Semgrep est installé localement :**
> ```bash
> semgrep --config p/php --error index.php
> ```

**Prenez le temps de lire chaque finding** en utilisant la grille de lecture ci-dessus.

**Questions :**

1. Combien de vulnérabilités Semgrep a-t-il détectées ? Quelle est leur sévérité ?
2. Pour chaque finding, notez : le nom de la règle, la ligne, et le type de vulnérabilité OWASP correspondant.
3. Y a-t-il des vulnérabilités dans `index.php` que Semgrep **n'a pas** détectées ? Pourquoi un outil SAST peut-il rater des vulnérabilités ?
4. Quelle est la différence entre SAST et DAST ? Dans quel ordre les intégrer dans une pipeline CI/CD ?

---

## Étape 2 — Comprendre les vulnérabilités

`index.php` contient **5 vulnérabilités intentionnelles**. Chaque fonction vulnérable est commentée avec son contexte d'exploitation.

| # | Vulnérabilité | Fonction | Impact |
|---|--------------|----------|--------|
| 1 | **Injection SQL** | `equipment_search()` | Lecture/modification/suppression de la base de données |
| 2 | **Injection de commandes OS** | `equipment_ping()` | Exécution de commandes arbitraires sur le serveur |
| 3 | **Cryptographie faible (MD5)** | `auth_login()` + init DB | Vol de mots de passe par rainbow tables |
| 4 | **Désérialisation non sécurisée** | `config_restore()` | PHP Object Injection → RCE via `__wakeup()` / `__destruct()` |
| 5 | **Injection de code PHP** | `alert_evaluate()` | Exécution arbitraire de code PHP côté serveur |

**Pour chaque vulnérabilité, lisez dans `index.php` :**
- Le commentaire `VULN #N` qui explique le mécanisme
- La ligne exacte que Semgrep a signalée
- L'URL de documentation dans la sortie du scan

---

## Étape 3 — Construire la pipeline CI/CD

Complétez `.github/workflows/security.yml` pour déclencher Semgrep à chaque push :

L'image `semgrep/semgrep` est déjà configurée dans le `container`.  
Votre seule tâche : écrire la commande `semgrep` dans le step `run:`.

```bash
# Une fois le fichier complété :
git add .github/workflows/security.yml
git commit -m "ci: pipeline Semgrep PHP"
git push
```

Ouvrez l'onglet **Actions** sur GitHub.  
La pipeline doit **échouer** — le code contient des vulnérabilités intentionnelles.  
Un job rouge avec `Exit code 1` est la réponse attendue.

---

## Étape 4 — Corriger les vulnérabilités

Corrigez chaque vulnérabilité dans `index.php`. Après chaque correction, relancez le scan pour vérifier :

```bash
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config p/php /src/index.php
```

| Vulnérabilité | Correction recommandée en PHP |
|--------------|------------------------------|
| Injection SQL | `$pdo->prepare("... WHERE x = ?")` + `->execute([$val])` |
| Injection de commandes | `filter_var($ip, FILTER_VALIDATE_IP)` + `escapeshellarg()` |
| MD5 faible | `password_hash($pass, PASSWORD_BCRYPT)` + `password_verify()` |
| `unserialize()` | `json_decode($raw, true)` |
| `eval()` | Liste blanche explicite — il n'existe pas de `eval()` sécurisé avec du contenu utilisateur |

Une fois toutes les corrections appliquées :

```bash
git add index.php
git commit -m "fix: vulnérabilités SAST corrigées"
git push
```

La pipeline doit maintenant **passer** (exit code 0, job vert).

---

## Livrables attendus

- La sortie complète de Semgrep **avant** correction (findings + exit code).
- Capture d'écran GitHub Actions : pipeline **en échec** sur le code vulnérable.
- Capture d'écran GitHub Actions : pipeline **en succès** après correction.
- Réponses aux 4 questions de l'Étape 1.

---

## Référence rapide — Semgrep

```bash
# Scanner avec plusieurs configs (PHP + OWASP Top 10)
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config p/php --config p/owasp-top-ten /src/index.php

# Sortie JSON (intégration avec d'autres outils)
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config p/php --json /src/index.php | jq '.results[].check_id'

# Scanner tout un répertoire
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config p/php /src/

# Afficher uniquement les findings ERROR
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config p/php --severity ERROR /src/index.php
```
