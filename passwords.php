[file name]: passwords.php
[file content begin]
<?php
require_once '../config/database.php';
require_once '../config/telegram_config.php';
require_once '../api/verify_session.php';

// Проверяем сессию
$session = SessionVerifier::middleware();
$user_id = $session['user_id'];

$database = new Database();
$db = $database->getConnection();

$method = $_SERVER['REQUEST_METHOD'];

// Для отладки
error_log("Passwords API called: Method=$method, UserID=$user_id");

switch ($method) {
    case 'GET':
        // Получить все пароли пользователя
        $query = "SELECT id, service_name, login, encrypted_password, iv, created_at, updated_at
                  FROM passwords WHERE user_id = :user_id 
                  AND deleted_at IS NULL
                  ORDER BY created_at DESC";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();

        $passwords = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'passwords' => $passwords,
            'count' => count($passwords)
        ]);
        break;

    case 'POST':
        // Добавить новый пароль
        $data = json_decode(file_get_contents('php://input'), true);

        // Логируем полученные данные
        error_log("POST data: " . print_r($data, true));

        // Проверяем лимит паролей
        $limit = $session['telegram']['is_premium'] ?? false ? 1000 : 100;

        $query = "SELECT COUNT(*) as count FROM passwords 
                  WHERE user_id = :user_id AND deleted_at IS NULL";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result['count'] >= $limit) {
            http_response_code(403);
            echo json_encode([
                'success' => false,
                'message' => 'Password limit reached',
                'limit' => $limit
            ]);
            exit;
        }

        $query = "INSERT INTO passwords (user_id, service_name, login, encrypted_password, iv) 
                  VALUES (:user_id, :service_name, :login, :encrypted_password, :iv)";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':service_name', $data['service_name']);
        $stmt->bindParam(':login', $data['login']);
        $stmt->bindParam(':encrypted_password', $data['encrypted_password']);
        $stmt->bindParam(':iv', $data['iv']);

        if ($stmt->execute()) {
            echo json_encode([
                'success' => true,
                'id' => $db->lastInsertId(),
                'created_at' => date('Y-m-d H:i:s')
            ]);
        } else {
            $error = $stmt->errorInfo();
            error_log("Database error: " . print_r($error, true));
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $error[2]]);
        }
        break;

    case 'PUT':
        // Обновить пароль - извлекаем ID из URL
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $pathParts = explode('/', $path);
        $id = end($pathParts);

        // Альтернативный способ получить ID
        if (!$id || !is_numeric($id)) {
            // Пробуем получить из query string
            $id = $_GET['id'] ?? 0;
        }

        $data = json_decode(file_get_contents('php://input'), true);

        // Логируем для отладки
        error_log("PUT request - ID: $id, UserID: $user_id");
        error_log("PUT data: " . print_r($data, true));

        if (!$id || !isset($data['login']) || !isset($data['encrypted_password']) || !isset($data['iv'])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Missing parameters',
                'received' => [
                    'id' => $id,
                    'login' => isset($data['login']),
                    'encrypted_password' => isset($data['encrypted_password']),
                    'iv' => isset($data['iv'])
                ]
            ]);
            exit;
        }

        $query = "UPDATE passwords 
                  SET login = :login, 
                      encrypted_password = :encrypted_password, 
                      iv = :iv,
                      updated_at = CURRENT_TIMESTAMP
                  WHERE id = :id AND user_id = :user_id AND deleted_at IS NULL";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':login', $data['login']);
        $stmt->bindParam(':encrypted_password', $data['encrypted_password']);
        $stmt->bindParam(':iv', $data['iv']);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            $affectedRows = $stmt->rowCount();
            error_log("Update executed. Affected rows: $affectedRows");

            if ($affectedRows > 0) {
                echo json_encode([
                    'success' => true,
                    'updated' => true,
                    'message' => 'Password updated successfully',
                    'affected_rows' => $affectedRows
                ]);
            } else {
                // Проверим, существует ли пароль
                $checkQuery = "SELECT id FROM passwords WHERE id = :id AND user_id = :user_id";
                $checkStmt = $db->prepare($checkQuery);
                $checkStmt->bindParam(':id', $id, PDO::PARAM_INT);
                $checkStmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                $checkStmt->execute();

                if ($checkStmt->fetch()) {
                    // Пароль существует, но возможно уже удален
                    $deletedQuery = "SELECT deleted_at FROM passwords WHERE id = :id";
                    $deletedStmt = $db->prepare($deletedQuery);
                    $deletedStmt->bindParam(':id', $id, PDO::PARAM_INT);
                    $deletedStmt->execute();
                    $deletedResult = $deletedStmt->fetch();

                    if ($deletedResult && $deletedResult['deleted_at']) {
                        http_response_code(410);
                        echo json_encode([
                            'success' => false,
                            'message' => 'Password has been deleted'
                        ]);
                    } else {
                        http_response_code(404);
                        echo json_encode([
                            'success' => false,
                            'message' => 'Password not found for update'
                        ]);
                    }
                } else {
                    http_response_code(404);
                    echo json_encode([
                        'success' => false,
                        'message' => 'Password not found or access denied'
                    ]);
                }
            }
        } else {
            $error = $stmt->errorInfo();
            error_log("Database update error: " . print_r($error, true));
            echo json_encode([
                'success' => false,
                'message' => 'Database error: ' . $error[2]
            ]);
        }
        break;

    case 'DELETE':
        // Мягкое удаление пароля
        $data = json_decode(file_get_contents('php://input'), true);
        $id = $data['id'] ?? 0;

        error_log("DELETE request - ID: $id, UserID: $user_id");

        $query = "UPDATE passwords SET deleted_at = CURRENT_TIMESTAMP 
                  WHERE id = :id AND user_id = :user_id";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            $affectedRows = $stmt->rowCount();
            echo json_encode([
                'success' => $affectedRows > 0,
                'deleted' => $affectedRows > 0,
                'affected_rows' => $affectedRows
            ]);
        } else {
            $error = $stmt->errorInfo();
            echo json_encode([
                'success' => false,
                'message' => 'Database error: ' . $error[2]
            ]);
        }
        break;

    default:
        http_response_code(405);
        echo json_encode([
            'success' => false,
            'message' => 'Method not allowed'
        ]);
        break;
}
?>
[file content end]