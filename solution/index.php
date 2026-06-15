<?php
/**
 * freemobile-netops-api — PHP Edition (VERSION CORRIGÉE)
 * =====================================================
 * Corrections appliquées :
 *   #1 SQL Injection    → requêtes préparées PDO (prepare / execute)
 *   #2 Command Injection → FILTER_VALIDATE_IP + escapeshellarg()
 *   #3 MD5 faible       → password_hash(BCRYPT) + password_verify()
 *   #4 unserialize()    → json_decode()
 *   #5 eval()           → liste blanche de règles prédéfinies
 * =====================================================
 */

declare(strict_types=1);

$db_path = '/tmp/netops-fixed.db';

// ── Initialisation ──────────────────────────────────────────────────────
function get_db(): PDO
{
    global $db_path;
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS equipment (
            id INTEGER PRIMARY KEY, hostname TEXT, ip TEXT,
            type TEXT, site TEXT, status TEXT
        )
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS auth_users (
            id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT
        )
    ");

    if (!$pdo->query("SELECT 1 FROM equipment LIMIT 1")->fetchColumn()) {
        $pdo->exec("
            INSERT INTO equipment VALUES
                (1,'rtr-paris-01','10.10.1.1' ,'router','Paris-CDG' ,'active'),
                (2,'bts-lyon-07' ,'10.20.7.3' ,'bts'   ,'Lyon-Part' ,'active'),
                (3,'nas-mars-04' ,'10.30.4.11','nas'   ,'Marseille' ,'maintenance'),
                (4,'rtr-bord-02' ,'10.40.2.5' ,'router','Bordeaux'  ,'active')
        ");

        // FIX #3 — bcrypt via password_hash() : sel automatique + coût adaptatif
        $s = $pdo->prepare("INSERT INTO auth_users VALUES (?,?,?,?)");
        $s->execute([1, 'admin',    password_hash('netops2024!', PASSWORD_BCRYPT), 'admin']);
        $s->execute([2, 'operator', password_hash('fr33mobile',  PASSWORD_BCRYPT), 'operator']);
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


// FIX #1 — Requête préparée : le pilote PDO sépare code SQL et données
// Le placeholder :q est lié à la valeur après compilation de la requête.
// Même si $q contient ' OR '1'='1, il est traité comme une donnée, pas du SQL.
function equipment_search(): never
{
    $q    = $_GET['q'] ?? '';
    $stmt = get_db()->prepare(
        "SELECT * FROM equipment WHERE hostname LIKE :q OR site LIKE :q"
    );
    $stmt->execute([':q' => "%$q%"]);
    json_out($stmt->fetchAll(PDO::FETCH_ASSOC));
}


// FIX #2 — Validation stricte de l'IP + escapeshellarg() en défense en profondeur
// filter_var() rejette tout ce qui n'est pas une IP valide (IPv4 ou IPv6).
// escapeshellarg() encapsule l'argument entre apostrophes et échappe les apostrophes
// internes — même si la validation est contournée, l'injection échoue.
function equipment_ping(): never
{
    $ip = body()['ip'] ?? '';

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        json_out(['error' => 'Adresse IP invalide (IPv4 ou IPv6 attendu)'], 400);
    }

    $output = shell_exec("ping -c 2 " . escapeshellarg($ip) . " 2>&1");
    json_out(['output' => $output]);
}


// FIX #3 — password_hash() + password_verify()
// password_hash() génère un sel aléatoire et l'inclut dans le hash final.
// Le coût bcrypt (défaut : 10) rend chaque test ~100ms — prohibitif en brute-force.
// password_verify() compare en temps constant pour éviter les timing attacks.
function auth_login(): never
{
    $data     = body();
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    $stmt = get_db()->prepare(
        "SELECT role, password_hash FROM auth_users WHERE username = ?"
    );
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && password_verify($password, $row['password_hash'])) {
        json_out(['status' => 'ok', 'role' => $row['role']]);
    }
    json_out(['status' => 'unauthorized'], 401);
}


// FIX #4 — json_decode() ne peut pas instancier d'objets PHP
// Contrairement à unserialize(), json_decode() produit uniquement des types
// scalaires, des tableaux et des stdClass — aucun __wakeup/__destruct ne peut
// être déclenché depuis des données JSON, quelle que soit leur contenu.
function config_restore(): never
{
    $raw    = file_get_contents('php://input');
    $config = json_decode($raw, true);

    if ($config === null && json_last_error() !== JSON_ERROR_NONE) {
        json_out(['error' => 'JSON invalide : ' . json_last_error_msg()], 400);
    }

    $keys = is_array($config) ? array_keys($config) : [];
    json_out(['status' => 'restored', 'keys' => $keys]);
}


// FIX #5 — Liste blanche : aucun eval(), aucune expression dynamique
// La règle est validée contre un ensemble fini de valeurs autorisées.
// L'évaluation est faite par du code PHP normal, pas par eval().
// Principe : réduire la surface d'attaque en éliminant le mécanisme
// plutôt qu'en essayant de l'assainir.
function alert_evaluate(): never
{
    $rule = body()['rule'] ?? '';

    $allowed = [
        'threshold > 90',
        'latency > 1000',
        'error_rate > 5',
    ];

    if (!in_array($rule, $allowed, true)) {
        json_out([
            'error'   => 'Règle non autorisée.',
            'allowed' => $allowed,
        ], 400);
    }

    // Évaluation sûre sans eval() — chaque règle est un cas explicite
    [$metric, , $threshold] = explode(' ', $rule);
    $current = match ($metric) {
        'threshold'  => 95,
        'latency'    => 1200,
        'error_rate' => 3,
        default      => 0,
    };
    $triggered = $current > (int) $threshold;

    json_out(['rule' => $rule, 'current_value' => $current, 'triggered' => $triggered]);
}
