<?php
/**
 * freemobile-netops-api — PHP Edition
 * =====================================================
 * VULNÉRABILITÉS SAST intentionnelles pour lab DevSecOps
 *
 * Outil de scan : semgrep --config p/php index.php
 * Documentation : https://semgrep.dev/p/php
 * =====================================================
 */

declare(strict_types=1);

$db_path = '/tmp/netops.db';

// ── Initialisation de la base de données ────────────────────────────────
function get_db(): PDO
{
    global $db_path;
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS equipment (
            id       INTEGER PRIMARY KEY,
            hostname TEXT,
            ip       TEXT,
            type     TEXT,
            site     TEXT,
            status   TEXT
        )
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS auth_users (
            id            INTEGER PRIMARY KEY,
            username      TEXT,
            password_hash TEXT,
            role          TEXT
        )
    ");

    if (!$pdo->query("SELECT 1 FROM equipment LIMIT 1")->fetchColumn()) {
        $pdo->exec("
            INSERT INTO equipment VALUES
                (1,'rtr-paris-01','10.10.1.1' ,'router','Paris-CDG'  ,'active'),
                (2,'bts-lyon-07' ,'10.20.7.3' ,'bts'   ,'Lyon-Part'  ,'active'),
                (3,'nas-mars-04' ,'10.30.4.11','nas'   ,'Marseille'  ,'maintenance'),
                (4,'rtr-bord-02' ,'10.40.2.5' ,'router','Bordeaux'   ,'active')
        ");

        // VULN #3 — MD5 pour stocker les mots de passe
        $s = $pdo->prepare("INSERT INTO auth_users VALUES (?,?,?,?)");
        $s->execute([1, 'admin',    md5('netops2024!'), 'admin']);
        $s->execute([2, 'operator', md5('fr33mobile'),  'operator']);
    }

    return $pdo;
}

// ── Helpers ─────────────────────────────────────────────────────────────
function json_out(mixed $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function body(): array
{
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

// ── Routeur ─────────────────────────────────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'];
$path   = strtok($_SERVER['REQUEST_URI'], '?');

match (true) {
    $method === 'GET'  && $path === '/health'                  => health(),
    $method === 'GET'  && $path === '/api/v1/equipment'        => equipment_list(),
    $method === 'GET'  && $path === '/api/v1/equipment/search' => equipment_search(),
    $method === 'POST' && $path === '/api/v1/equipment/ping'   => equipment_ping(),
    $method === 'POST' && $path === '/api/v1/auth/login'       => auth_login(),
    $method === 'POST' && $path === '/api/v1/config/restore'   => config_restore(),
    $method === 'POST' && $path === '/api/v1/alerts/evaluate'  => alert_evaluate(),
    default                                                    => json_out(['error' => 'Not Found'], 404),
};


// ── Handlers ────────────────────────────────────────────────────────────

function health(): never
{
    json_out(['status' => 'ok', 'service' => 'freemobile-netops-api-php']);
}

function equipment_list(): never
{
    $rows = get_db()->query("SELECT * FROM equipment")->fetchAll(PDO::FETCH_ASSOC);
    json_out($rows);
}


// ============================================================
// VULN #1 — Injection SQL
// Règle Semgrep : php.lang.security.injection.tainted-sql-string
//
// Semgrep fait de l'analyse de flux (taint analysis) : il trace $q
// depuis sa source ($_GET) jusqu'au "sink" dangereux (query() avec
// concaténation). Même si le code semble anodin, le flux est compromis.
//
// Exploitation → GET /api/v1/equipment/search?q=' OR '1'='1
//                → retourne tous les équipements sans restriction
// ============================================================
function equipment_search(): never
{
    $q   = $_GET['q'] ?? '';
    $pdo = get_db();

    // Concaténation directe de $_GET dans la requête SQL → injection possible
    $rows = $pdo->query(
        "SELECT * FROM equipment WHERE hostname LIKE '%$q%' OR site LIKE '%$q%'"
    )->fetchAll(PDO::FETCH_ASSOC);

    json_out($rows);
}


// ============================================================
// VULN #2 — Injection de commandes OS
// Règle Semgrep : php.lang.security.command-injection.exec-use
//
// shell_exec() passe la commande à /bin/sh qui interprète les
// métacaractères shell : ; | && ` $() etc.
// Sans validation, un attaquant contrôle le shell du serveur.
//
// Exploitation → POST {"ip": "10.10.1.1; cat /etc/passwd"}
//                → exécute cat /etc/passwd sur le serveur
// ============================================================
function equipment_ping(): never
{
    $ip = body()['ip'] ?? '';

    // shell_exec() avec entrée utilisateur brute → injection de commandes OS
    $output = shell_exec("ping -c 2 $ip 2>&1");

    json_out(['output' => $output]);
}


// ============================================================
// VULN #3 — Cryptographie faible (MD5)
// Règle Semgrep : php.lang.security.crypto.use-of-md5
//
// MD5 est conçu pour la vitesse, non pour les mots de passe.
// Un GPU moderne calcule ~10 milliards de MD5/seconde.
// Sans sel, les hashes sont cassables instantanément par rainbow tables.
//
// PHP fournit password_hash(PASSWORD_BCRYPT) qui : ajoute un sel
// aléatoire, est intentionnellement lent (coût paramétrable),
// et résiste aux rainbow tables.
// ============================================================
function auth_login(): never
{
    $data     = body();
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    // MD5 sans sel → cassable par tables arc-en-ciel / brute-force GPU
    $hashed = md5($password);

    $stmt = get_db()->prepare(
        "SELECT role FROM auth_users WHERE username = ? AND password_hash = ?"
    );
    $stmt->execute([$username, $hashed]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $row
        ? json_out(['status' => 'ok', 'role' => $row['role']])
        : json_out(['status' => 'unauthorized'], 401);
}


// ============================================================
// VULN #4 — Désérialisation non sécurisée (PHP Object Injection)
// Règle Semgrep : php.lang.security.deserialize.unserialize-use
//
// unserialize() peut instancier n'importe quelle classe en mémoire.
// Si une classe disponible possède __wakeup() ou __destruct() avec
// des effets de bord (écriture fichier, exec, requête réseau…),
// un payload malveillant peut déclencher du RCE.
// Cette technique s'appelle "PHP Object Injection" (POI/POP chain).
//
// Alternative sûre : json_decode() ne peut pas instancier d'objets PHP.
// ============================================================
function config_restore(): never
{
    $raw = file_get_contents('php://input');

    // unserialize() sur données HTTP → PHP Object Injection → RCE potentiel
    $config = unserialize($raw);

    $keys = is_array($config) ? array_keys($config) : [];
    json_out(['status' => 'restored', 'keys' => $keys]);
}


// ============================================================
// VULN #5 — Injection de code PHP (eval)
// Règle Semgrep : php.lang.security.eval-use
//
// eval() compile et exécute une chaîne comme du code PHP natif.
// Avec une entrée utilisateur, c'est une porte ouverte sur le serveur.
// Il n'existe pas de version "sécurisée" de eval() avec des données utilisateur.
//
// Exploitation → POST {"rule": "system('id')"}
//                → exécute la commande id sur le serveur
// ============================================================
function alert_evaluate(): never
{
    $rule = body()['rule'] ?? '';

    // eval() sur entrée utilisateur → exécution arbitraire de code PHP
    $result = eval("return $rule;");

    json_out(['result' => $result]);
}
