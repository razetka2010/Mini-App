<?php
require_once '../config/database.php';
require_once '../config/telegram_auth.php';
require_once '../config/telegram_config.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Methods: POST');

// Проверяем метод запроса
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(array('success' => false, 'message' => 'Method not allowed'));
    exit;
}

// Проверяем CORS origin
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if (!TelegramConfig::isOriginAllowed($origin)) {
    http_response_code(403);
    echo json_encode(array('success' => false, 'message' => 'Origin not allowed'));
    exit;
}

// Разрешаем только Telegram и локальную разработку
header('Access-Control-Allow-Origin: ' . $origin);

// Получаем данные
$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['initData'])) {
    http_response_code(400);
    echo json_encode(array('success' => false, 'message' => 'No initData provided'));
    exit;
}

$initData = $input['initData'];

// ВАЖНО: Проверяем подпись Telegram
if (!TelegramAuth::validate($initData, TelegramConfig::BOT_TOKEN)) {
    http_response_code(401);
    $response = array(
        'success' => false,
        'message' => 'Invalid Telegram signature'
    );

    // Добавляем отладочную информацию только на localhost
    if ($_SERVER['HTTP_HOST'] === 'localhost' || strpos($_SERVER['HTTP_HOST'], 'localhost') !== false) {
        $response['debug'] = 'Signature check failed';
    }

    echo json_encode($response);
    exit;
}

// Проверяем свежесть данных (не старше 1 дня)
if (!TelegramAuth::isFresh($initData, 86400)) {
    http_response_code(401);
    echo json_encode(array('success' => false, 'message' => 'Data expired'));
    exit;
}

// Получаем данные пользователя
$user = TelegramAuth::getUserData($initData);
if (!$user) {
    http_response_code(400);
    echo json_encode(array('success' => false, 'message' => 'Invalid user data'));
    exit;
}

// Подключаемся к БД
try {
    $database = new Database();
    $db = $database->getConnection();

    // Проверяем/создаем пользователя
    $query = "INSERT INTO users (telegram_id, username, first_name, last_name, language_code, is_premium) 
              VALUES (:telegram_id, :username, :first_name, :last_name, :language_code, :is_premium)
              ON DUPLICATE KEY UPDATE 
              username = VALUES(username),
              first_name = VALUES(first_name),
              last_name = VALUES(last_name),
              language_code = VALUES(language_code),
              is_premium = VALUES(is_premium),
              last_login = CURRENT_TIMESTAMP";

    $stmt = $db->prepare($query);
    $stmt->bindParam(':telegram_id', $user['id']);
    $stmt->bindParam(':username', $user['username']);
    $stmt->bindParam(':first_name', $user['first_name']);
    $stmt->bindParam(':last_name', $user['last_name']);
    $stmt->bindParam(':language_code', $user['language_code']);
    $isPremium = $user['is_premium'] ? 1 : 0;
    $stmt->bindParam(':is_premium', $isPremium, PDO::PARAM_INT);

    if (!$stmt->execute()) {
        throw new Exception('Failed to save user');
    }

    // Получаем полные данные пользователя из БД
    $query = "SELECT id, telegram_id, username, first_name, last_name, created_at 
              FROM users WHERE telegram_id = :telegram_id";

    $stmt = $db->prepare($query);
    $stmt->bindParam(':telegram_id', $user['id']);
    $stmt->execute();
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    // Генерируем сессионный токен (JWT-like)
    $sessionToken = generateSessionToken($user['id'], $userData['id']);

    // Логируем успешный вход (опционально)
    logAuth($db, $userData['id'], $_SERVER['REMOTE_ADDR']);

    // Возвращаем успешный ответ
    echo json_encode(array(
        'success' => true,
        'user' => array(
            'telegram' => $user,
            'database' => $userData
        ),
        'session_token' => $sessionToken,
        'permissions' => array(
            'can_add' => true,
            'can_delete' => true,
            'max_passwords' => $user['is_premium'] ? 1000 : 100
        )
    ));

} catch (Exception $e) {
    error_log("Auth error: " . $e->getMessage());
    http_response_code(500);
    $response = array(
        'success' => false,
        'message' => 'Database error'
    );

    if ($_SERVER['HTTP_HOST'] === 'localhost' || strpos($_SERVER['HTTP_HOST'], 'localhost') !== false) {
        $response['debug'] = $e->getMessage();
    }

    echo json_encode($response);
}

/**
 * Генерирует сессионный токен
 */
function generateSessionToken($telegramId, $userId) {
    $payload = array(
        'telegram_id' => $telegramId,
        'user_id' => $userId,
        'iat' => time(),
        'exp' => time() + (7 * 24 * 60 * 60), // 7 дней
        'iss' => 'telegram-password-manager'
    );

    // В реальном приложении используйте JWT с секретным ключом
    // Для простоты используем base64
    return base64_encode(json_encode($payload));
}

/**
 * Логирует вход пользователя
 */
function logAuth($db, $userId, $ip) {
    try {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        $query = "INSERT INTO auth_logs (user_id, ip_address, user_agent) 
                  VALUES (:user_id, :ip, :ua)";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $userId);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':ua', $userAgent);
        $stmt->execute();
    } catch (Exception $e) {
        // Не прерываем основной процесс из-за ошибки логирования
        error_log("Auth log error: " . $e->getMessage());
    }
}
?>
