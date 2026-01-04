<?php
require_once '../config/database.php';

$data = json_decode(file_get_contents('php://input'), true);

if (!$data || !isset($data['initData'])) {
    echo json_encode(['success' => false, 'message' => 'No data']);
    exit;
}

// В реальном приложении нужно проверять хеш от Telegram
// Для упрощения пропускаем проверку на данном этапе

// Парсим initData
parse_str($data['initData'], $initDataArray);

if (!isset($initDataArray['user'])) {
    echo json_encode(['success' => false, 'message' => 'No user data']);
    exit;
}

$user = json_decode($initDataArray['user'], true);

// Подключаемся к БД
$database = new Database();
$db = $database->getConnection();

// Проверяем/создаем пользователя
$query = "INSERT INTO users (telegram_id, username, first_name, last_name) 
          VALUES (:telegram_id, :username, :first_name, :last_name)
          ON DUPLICATE KEY UPDATE 
          username = VALUES(username),
          first_name = VALUES(first_name),
          last_name = VALUES(last_name)";

$stmt = $db->prepare($query);
$stmt->bindParam(':telegram_id', $user['id']);
$stmt->bindParam(':username', $user['username']);
$stmt->bindParam(':first_name', $user['first_name']);
$stmt->bindParam(':last_name', $user['last_name']);

if ($stmt->execute()) {
    // Получаем ID пользователя
    $query = "SELECT id FROM users WHERE telegram_id = :telegram_id";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':telegram_id', $user['id']);
    $stmt->execute();
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        'success' => true,
        'user' => $user,
        'user_id' => $userData['id']
    ]);
} else {
    echo json_encode(['success' => false, 'message' => 'Database error']);
}
?>

