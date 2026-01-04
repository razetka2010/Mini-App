<?php
require_once '../config/database.php';
require_once '../config/telegram_config.php';

class SessionVerifier {

    /**
     * Проверяет сессионный токен
     * @param string $token
     * @return array|false
     */
    public static function verifyToken($token) {
        try {
            $decoded = json_decode(base64_decode($token), true);

            if (!$decoded) {
                return false;
            }

            // Проверяем срок действия
            if (!isset($decoded['exp']) || $decoded['exp'] < time()) {
                return false;
            }

            // Проверяем обязательные поля
            if (!isset($decoded['telegram_id']) || !isset($decoded['user_id'])) {
                return false;
            }

            // Проверяем в БД, что пользователь существует
            $database = new Database();
            $db = $database->getConnection();

            $query = "SELECT id FROM users 
                      WHERE id = :user_id AND telegram_id = :telegram_id 
                      AND deleted_at IS NULL";

            $stmt = $db->prepare($query);
            $stmt->bindParam(':user_id', $decoded['user_id']);
            $stmt->bindParam(':telegram_id', $decoded['telegram_id']);
            $stmt->execute();

            if ($stmt->fetch()) {
                return $decoded;
            }

            return false;

        } catch (Exception $e) {
            error_log("Session verification error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Middleware для проверки сессии
     */
    public static function middleware() {
        $headers = getallheaders();
        $token = $headers['Authorization'] ??
            $headers['authorization'] ??
            ($_GET['token'] ?? '');

        // Убираем 'Bearer ' если есть
        $token = str_replace('Bearer ', '', $token);

        if (!$token) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'No token provided']);
            exit;
        }

        $session = self::verifyToken($token);

        if (!$session) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Invalid or expired token']);
            exit;
        }

        return $session;
    }
}
?>